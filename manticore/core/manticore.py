import os
import itertools
import logging
import sys
import time
import typing
import random
import weakref
from typing import Callable

from contextlib import contextmanager

import functools
import shlex

from ..core.plugin import Plugin, IntrospectionAPIPlugin, StateDescriptor
from ..core.smtlib import Expression, SOLVER_STATS
from ..core.state import StateBase
from ..core.workspace import ManticoreOutput
from ..exceptions import ManticoreError
from ..utils import config
from ..utils.deprecated import deprecated
from ..utils.enums import StateLists, MProcessingType
from ..utils.event import Eventful
from ..utils.helpers import PickleSerializer, pretty_print_state_descriptors, deque
from ..utils.log import set_verbosity
from ..utils.nointerrupt import WithKeyboardInterruptAs
from .workspace import Workspace, Testcase
from .worker import (
    WorkerSingle,
    WorkerThread,
    WorkerProcess,
    DaemonThread,
    LogCaptureWorker,
    state_monitor,
)

from multiprocessing.managers import SyncManager
import threading
import ctypes
import signal

logger = logging.getLogger(__name__)

consts = config.get_group("core")
consts.add("timeout", default=0, description="Timeout, in seconds, for Manticore invocation")
consts.add(
    "cluster",
    default=False,
    description="If True enables to run workers over the network UNIMPLEMENTED",#如果True,允许在未实现的网络上运行worker
)
consts.add(
    "procs",
    default=12,
    description="Number of parallel processes to spawn in order to run every task, including solvers",#为了运行每个任务(包括求解器)而生成的并行进程数
)

proc_type = MProcessingType.threading
if sys.platform != "linux":
    logger.warning("Manticore is only supported on Linux. Proceed at your own risk!")
    proc_type = MProcessingType.threading

consts.add(
    "mprocessing",
    default=proc_type,
    description="single: No multiprocessing at all. Single process.\n threading: use threads\n multiprocessing: use forked processes",
)#single:完全不进行多处理。单的过程。threading:使用线程multiprocessing:使用fork进程
consts.add(
    "seed",
    default=random.getrandbits(32),
    description="The seed to use when randomly selecting states",
)


class ManticoreBase(Eventful):
    _published_events = {"solve"}

    def _manticore_single(self):
        self._worker_type = WorkerSingle

        class FakeLock:
            def _nothing(self, *args, **kwargs):
                pass

            acquire = _nothing
            release = _nothing
            __enter__ = _nothing
            __exit__ = _nothing
            notify_all = _nothing
            wait = _nothing

            def wait_for(self, condition, *args, **kwargs):
                if not condition():
                    raise Exception("Deadlock: Waiting for CTRL+C")

        self._lock = FakeLock()
        self._killed = ctypes.c_bool(False)
        self._running = ctypes.c_bool(False)
        self._ready_states = []
        self._terminated_states = []
        self._busy_states = []
        self._killed_states = []
        self._log_queue = deque(maxlen=5000)
        self._shared_context = {}

    def _manticore_threading(self):
        self._worker_type = WorkerThread
        self._lock = threading.Condition()
        self._killed = ctypes.c_bool(False)
        self._running = ctypes.c_bool(False)
        self._ready_states = []
        self._terminated_states = []
        self._busy_states = []
        self._killed_states = []
        self._log_queue = deque(maxlen=5000)
        self._shared_context = {}

    def _manticore_multiprocessing(self):
        def raise_signal():
            signal.signal(signal.SIGINT, signal.SIG_IGN)

        self._worker_type = WorkerProcess
        # This is the global manager that will handle all shared memory access#这个全局管理器将处理所有共享内存访问
        # See. https://docs.python.org/3/library/multiprocessing.html#multiprocessing.managers.SyncManager
        self._manager = SyncManager()
        self._manager.start(raise_signal)
        # The main manticore lock. Acquire this for accessing shared objects#主蝎狮锁。获取这个以访问共享对象
        # THINKME: we use the same lock to access states lists and shared contexts# THINKME:我们使用相同的锁来访问状态列表和共享上下文
        self._lock = self._manager.Condition()
        self._killed = self._manager.Value(bool, False)
        self._running = self._manager.Value(bool, False)
        # List of state ids of States on storage存储的状态id列表
        self._ready_states = self._manager.list()
        self._terminated_states = self._manager.list()
        self._busy_states = self._manager.list()
        self._killed_states = self._manager.list()
        # The multiprocessing queue is much slower than the deque when it gets full, so we
        # triple the size in order to prevent that from happening.
        #当多处理队列被填满时，它比deque队列要慢得多，所以我们将其大小增加了三倍，以防止这种情况发生。
        self._log_queue = self._manager.Queue(15000)
        self._shared_context = self._manager.dict()
        self._context_value_types = {list: self._manager.list, dict: self._manager.dict}

    # Decorators added first for convenience.为了方便，首先添加了装饰器。
    def sync(func: Callable) -> Callable:  # type: ignore
        """Synchronization decorator"""

        @functools.wraps(func)
        def newFunction(self, *args, **kw):
            with self._lock:
                return func(self, *args, **kw)

        return newFunction

    def at_running(func: Callable) -> Callable:  # type: ignore
        """Allows the decorated method to run only when manticore is actively
        exploring states允许修饰的方法只在蝎尾正在积极探索状态时运行
        """

        @functools.wraps(func)
        def newFunction(self, *args, **kw):
            if not self.is_running():
                raise ManticoreError(f"{func.__name__} only allowed while exploring states")
            return func(self, *args, **kw)

        return newFunction

    def at_not_running(func: Callable) -> Callable:  # type: ignore
        """Allows the decorated method to run only when manticore is NOT
        exploring states允许修饰的方法只在manticore处于NOT探索状态时运行
        """

        @functools.wraps(func)
        def newFunction(self, *args, **kw):
            if self.is_running():
                logger.error("Calling at running not allowed")
                raise ManticoreError(f"{func.__name__} only allowed while NOT exploring states")
            return func(self, *args, **kw)

        return newFunction

    def only_from_main_script(func: Callable) -> Callable:  # type: ignore
        """Allows the decorated method to run only from the main manticore script允许修饰过的方法只从主manticore脚本运行"""

        @functools.wraps(func)
        def newFunction(self, *args, **kw):
            if not self.is_main() or self.is_running():
                logger.error("Calling from worker or forked process not allowed")
                raise ManticoreError(f"{func.__name__} only allowed from main")
            return func(self, *args, **kw)

        return newFunction

    _published_events = {
        "run",
        "start_worker",
        "terminate_worker",
        "transition_state",
        "enqueue_state",
        "fork_state",
        "load_state",
        "save_state",
        "remove_state",
        "terminate_state",
        "kill_state",
        "execute_instruction",
        "terminate_execution",
    }

    def __init__(
        self,
        initial_state,
        workspace_url=None,
        outputspace_url=None,
        introspection_plugin_type: type = IntrospectionAPIPlugin,
        **kwargs,
    ):
        """
        Manticore symbolically explores program states.


        **Manticore phases**

        Manticore has multiprocessing capabilities. Several worker processes
        could be registered to do concurrent exploration of the READY states.
        Manticore can be itself at different phases: STANDBY, RUNNING.

        .. code-block:: none

                      +---------+               +---------+
                ----->| STANDBY +<------------->+ RUNNING |
                      +---------+               +----+----+

        *Phase STANDBY*

        Manticore starts at STANDBY with a single initial state. Here the user
        can inspect, modify and generate testcases for the different states. The
        workers are paused and not doing any work. Actions: run()
        Manticore以STANDBY启动，只有一个初始状态。在这里，用户可以检查、修改和生成不同状态的测试用例。工人们暂停工作，不做任何工作。

        *Phase RUNNING*

        At RUNNING the workers consume states from the READY state list and
        potentially fork new states or terminate states. A RUNNING manticore can
        be stopped back to STANDBY. Actions: stop()
        在运行时，工作人员从READY状态列表中消费状态，并可能fork新的状态或终止状态。正在运行的蝎尾可以停止到STANDBY状态。

        **States and state lists**

        A state contains all the information of the running program at a given
        moment. State snapshots are saved to the workspace often. Internally
        Manticore associates a fresh id with each saved state. The memory copy
        of the state is then changed by the emulation of the specific arch.
        Stored snapshots are periodically updated using: _save() and _load().
        状态包含给定时刻运行程序的所有信息。状态快照经常保存到工作区中。
        在内部，Manticore将一个新的id与每个保存的状态关联起来。
        然后通过模拟特定的arch来改变状态的内存副本。使用_save()和_load()定期更新存储的快照。
        .. code-block:: none

                      _save     +-------------+  _load
            State  +----------> |  WORKSPACE  +----------> State
                                +-------------+

        During exploration Manticore spawns a number of temporary states that are
        maintained in different lists:在探索过程中，manticore产生了许多临时状态，这些状态在不同的列表中保持:

        .. code-block:: none

                Initial
                State
                  |   +-+---{fork}-----+
                  |   | |              |
                  V   V V              |
                +---------+        +---+----+      +------------+
                |  READY  +------->|  BUSY  +----->| TERMINATED |
                +---------+        +---+----+      +------------+
                     |
                     |                             +--------+
                     +---------------------------->| KILLED |
                                                   +--------+

        At any given time a state must be at the READY, BUSY, TERMINATED or
        KILLED list.在任何给定的时间，一个状态必须在READY, BUSY, TERMINATED或KILLED列表中。

        *State list: READY*

        The READY list holds all the runnable states. Internally a state is
        added to the READY list via method `_put_state(state)`. Workers take
        states from the READY list via the `_get_state(wait=True|False)` method.
        A worker mainloop will consume states from the READY list and mark them
        as BUSYwhile working on them. States in the READY list can go to BUSY or
        KILLED
        READY列表保存了所有的可运行状态。
        在内部，一个状态通过方法' _put_state(state) '添加到READY列表中。
        工作线程通过' _get_state(wait=True|False) '方法从READY列表中获取状态。
        worker主循环将使用READY列表中的状态，并将它们标记为BUSYwhile。READY列表中的州可以是BUSY或KILLED

        *State list: BUSY*

        When a state is selected for exploration from the READY list it is
        marked as busy and put in the BUSY list. States being explored will be
        constantly modified  and only saved back to storage when moved out of
        the BUSY list. Hence, when at BUSY the stored copy of the state will be
        potentially outdated. States in the BUSY list can go to TERMINATED,
        KILLED or they can be {forked} back to READY. The forking process
        could involve generating new child states and removing the parent
        from all the lists.
        当从READY列表中选择一个状态进行探索时，它将被标记为busy并放入busy列表中。
        正在探索的状态将不断地被修改，并且只有在移出BUSY列表时才会被保存回存储。
        因此，当处于BUSY时，存储的状态副本可能已经过时。
        BUSY列表中的状态可以转到TERMINATED、KILLED，或者它们可以被{fork}返回READY。
        fork过程可能包括生成新的子状态并从所有列表中删除父状态。

        *State list: TERMINATED*

        TERMINATED contains states that have reached a final condition and raised
        TerminateState. Worker's mainloop simply moves the states that requested
        termination to the TERMINATED list. This is a final list.
        TERMINATED包含已达到最终条件并引发TerminateState的状态。
        Worker的主循环只是将请求终止的状态移动到TERMINATED列表中。这是最终的清单。

        ```An inherited Manticore class like ManticoreEVM could internally revive
        the states in TERMINATED that pass some condition and move them back to
        READY so the user can apply a following transaction.```
        像ManticoreEVM这样的继承的Manticore类可以在内部恢复TERMINATED中传递的一些条件的状态，并将它们移回READY，以便用户可以应用接下来的事务。
        *State list: KILLED*

        KILLED contains all the READY and BUSY states found at a cancel event.
        Manticore supports interactive analysis and has a prominent event system.
        A user can stop or cancel the exploration at any time. The unfinished
        states caught in this situation are simply moved to their own list for
        further user action. This is a final list.
        kill包含在取消事件中发现的所有READY和BUSY状态。
        Manticore支持交互分析，并有一个突出的事件系统。
        用户可以在任何时候停止或取消探索。
        在这种情况下捕获的未完成状态将被简单地移动到它们自己的列表中，以供进一步的用户操作。
        这是最终的清单。

        :param initial_state: the initial root `State` object to start from
        :param workspace_url: workspace folder name
        :param outputspace_url: Folder to place final output. Defaults to workspace用于放置最终输出的文件夹。默认的工作空间
        :param kwargs: other kwargs, e.g.
        """
        super().__init__()
        random.seed(consts.seed)
        {
            consts.mprocessing.single: self._manticore_single,
            consts.mprocessing.threading: self._manticore_threading,
            consts.mprocessing.multiprocessing: self._manticore_multiprocessing,
        }[consts.mprocessing]()

        if any(
            not hasattr(self, x)
            for x in (
                "_worker_type",
                "_lock",
                "_running",
                "_killed",
                "_ready_states",
                "_terminated_states",
                "_killed_states",
                "_busy_states",
                "_shared_context",
            )
        ):
            raise ManticoreError("Need to instantiate one of: ManticoreNative, ManticoreThreads..")

        # The workspace and the output
        # Manticore will use the workspace to save and share temporary states.
        # Manticore will use the output to save the final reports.
        # By default the output folder and the workspace folder are the same.
        # Check type, default to fs:
        #工作区和输出
        # Manticore将使用工作区来保存和共享临时状态。
        # Manticore将使用输出保存最终的报告。
        #默认情况下，输出文件夹和工作空间文件夹是相同的。
        #检查类型，默认为fs:
        if isinstance(workspace_url, str):
            if ":" not in workspace_url:
                workspace_url = f"fs:{workspace_url}"
        else:
            if workspace_url is not None:
                raise TypeError(f"Invalid workspace type: {type(workspace_url).__name__}")
        self._workspace = Workspace(workspace_url)
        # reuse the same workspace if not specified#重用相同的工作空间，如果没有指定
        if outputspace_url is None:
            outputspace_url = workspace_url
        if outputspace_url is None:
            outputspace_url = f"fs:{self._workspace.uri}"
        self._output = ManticoreOutput(outputspace_url)

        # The set of registered plugins
        # The callback methods defined in the plugin object will be called when
        # the different type of events occur over an exploration.
        # Note that each callback will run in a worker process and that some
        # careful use of the shared context is needed.
        #已注册插件的集合
        #在插件对象中定义的回调方法将被调用
        #不同类型的事件发生在一个探索。
        #注意，每个回调将在一个工作进程中运行
        #需要谨慎使用共享上下文。
        self.plugins: typing.Dict[str, Plugin] = {}
        assert issubclass(
            introspection_plugin_type, IntrospectionAPIPlugin
        ), "Introspection plugin must be a subclass of IntrospectionAPIPlugin"
        self.register_plugin(introspection_plugin_type())

        # Set initial root state
        if not isinstance(initial_state, StateBase):
            raise TypeError(f"Invalid initial_state type: {type(initial_state).__name__}")
        self._put_state(initial_state)

        nworkers = max(consts.procs // initial_state._solver.ncores, 1)
        # Workers will use manticore __dict__ So lets spawn them last
        self._workers = [self._worker_type(id=i, manticore=self) for i in range(nworkers)]

        # Create log capture worker. We won't create the rest of the daemons until .run() is called
        #创建日志捕获工人。在调用.run()之前，我们不会创建其余的守护进程
        self._daemon_threads: typing.Dict[int, DaemonThread] = {
            -1: LogCaptureWorker(id=-1, manticore=self)
        }
        self._daemon_callbacks: typing.List[typing.Callable] = []

        self._snapshot = None
        self._main_id = os.getpid(), threading.current_thread().ident

    def is_main(self):
        """True if called from the main process/script
        Note: in "single" mode this is _most likely_ True"""
        return self._main_id == (os.getpid(), threading.current_thread().ident)

    @sync
    @only_from_main_script
    def take_snapshot(self):
        """Copy/Duplicate/backup all ready states and save it in a snapshot.拷贝/复制/备份所有就绪状态，并保存在一个快照中。
        If there is a snapshot already saved it will be overrwritten如果已经保存了快照，则将覆盖该快照
        """
        if self._snapshot is not None:
            logger.info("Overwriting a snapshot of the ready states")
        snapshot = []
        for state_id in self._ready_states:
            state = self._load(state_id)
            # Re-save the state in case the user changed its data重新保存状态，以防用户更改其数据
            snapshot.append(self._save(state))
        self._snapshot = snapshot

    @sync
    @only_from_main_script
    def goto_snapshot(self):
        """REMOVE current ready states and replace them with the saved states移除当前准备状态，并将其替换为快照中保存的状态
        in a snapshot"""
        if not self._snapshot:
            raise ManticoreError("No snapshot to go to")
        self.clear_ready_states()
        for state_id in self._snapshot:
            self._publish("will_enqueue_state", None, can_raise=False)
            self._ready_states.append(state_id)
            self._publish("did_enqueue_state", state_id, can_raise=False)
        self._snapshot = None

    @sync
    @only_from_main_script
    def clear_snapshot(self):
        """ Remove any saved states """删除所有保存的状态
        if self._snapshot:
            for state_id in self._snapshot:
                self._remove(state_id)
        self._snapshot = None

    @sync
    @at_not_running
    def clear_terminated_states(self):
        """ Remove all states from the terminated list """"""从终止列表中删除所有状态"""
        terminated_states_ids = tuple(self._terminated_states)
        for state_id in terminated_states_ids:
            self._terminated_states.remove(state_id)
            self._remove(state_id)
        assert self.count_terminated_states() == 0

    @sync
    @at_not_running
    def clear_ready_states(self):
        """ Remove all states from the ready list """"""从准备列表中删除所有状态"""
        ready_states_ids = tuple(self._ready_states)
        for state_id in ready_states_ids:
            self._ready_states.remove(state_id)
            self._remove(state_id)
        assert self.count_ready_states() == 0

    def __str__(self):
        return f"<{str(type(self))[8:-2]}| Alive States: {self.count_ready_states()}; Running States: {self.count_busy_states()} Terminated States: {self.count_terminated_states()} Killed States: {self.count_killed_states()} Started: {self._running.value} Killed: {self._killed.value}>"

    @classmethod
    def from_saved_state(cls, filename: str, *args, **kwargs):
        """
        Creates a Manticore object starting from a serialized state on the disk.从磁盘上的序列化状态开始创建Manticore对象。

        :param filename: File to load the state from
        :param args: Arguments forwarded to the Manticore object
        :param kwargs: Keyword args forwarded to the Manticore object
        :return: An instance of a subclass of ManticoreBase with the given initial state:给定初始状态的ManticoreBase子类的实例
        """
        from ..utils.helpers import PickleSerializer

        with open(filename, "rb") as fd:
            deserialized = PickleSerializer().deserialize(fd)

        return cls(deserialized, *args, **kwargs)

    def _fork(self, state, expression, policy="ALL", setstate=None):
        """
        Fork state on expression concretizations.关于表达具体化的分叉状态。
        Using policy build a list of solutions for expression.使用策略构建表达式的解决方案列表。
        For the state on each solution setting the new state with setstate对于每个解决方案上的状态，使用setstate设置新状态

        For example if expression is a Bool it may have 2 solutions. True or False.例如，如果表达式是Bool，它可能有两个解决方案。真或假。

                                 Parent
                            (expression = ??)

                   Child1                         Child2
            (expression = True)             (expression = False)
               setstate(True)                   setstate(False)

        The optional setstate() function is supposed to set the concrete value
        in the child state.可选的setstate()函数用于设置子状态中的具体值。

        Parent state is removed from the busy list and the child states are added
        to the ready list.父状态从繁忙列表中删除，子状态添加到就绪列表中。

        """
        assert isinstance(expression, Expression), f"{type(expression)} is not an Expression"

        if setstate is None:

            def setstate(x, y):
                pass

        # Find a set of solutions for expression#找到表达式的一组解
        solutions = state.concretize(expression, policy)

        if not solutions:
            raise ManticoreError("Forking on unfeasible constraint set")

        logger.debug(
            "Forking. Policy: %s. Values: %s", policy, ", ".join(f"0x{sol:x}" for sol in solutions)
        )

        self._publish("will_fork_state", state, expression, solutions, policy)

        # Build and enqueue a state for each solution#为每个解决方案构建并排队一个状态
        children = []
        for new_value in solutions:
            with state as new_state:
                new_state.constrain(expression == new_value)

                # and set the PC of the new state to the concrete pc-dest
                # (or other register or memory address to concrete)
                #并将PC的新状态设置为具体的PC -dest
                #(或其他寄存器或内存地址设置为具体的PC-dest)
                setstate(new_state, new_value)

                # enqueue new_state, assign new state id排队new_state，分配新的state id
                new_state_id = self._put_state(new_state)

                # maintain a list of children for logging purpose#为日志目的维护一个子列表
                children.append(new_state_id)

        self._publish("did_fork_state", state, expression, solutions, policy, children)
        logger.debug("Forking current state %r into states %r", state.id, children)

        with self._lock:
            self._busy_states.remove(state.id)
            self._remove(state.id)
            state._id = None
            self._lock.notify_all()

    @staticmethod
    @deprecated("Use utils.log.set_verbosity instead.")
    def verbosity(level):
        """Sets global verbosity level.
        This will activate different logging profiles globally depending
        on the provided numeric value设置全局冗长级别。这将根据提供的数值全局激活不同的日志配置文件
        """
        set_verbosity(level)

    # State storage
    @Eventful.will_did("save_state", can_raise=False)
    def _save(self, state, state_id=None) -> int:
        """Store or update a state in secondary storage under state_id.
        Use a fresh id is None is provided.在二级存储中使用state_id存储或更新状态。使用一个新鲜的id是没有提供。

        :param state: A manticore State
        :param state_id: if not None force state_id (overwrite)
        :type state_id: int or None
        :returns: the state id used
        """
        state._id = self._workspace.save_state(state, state_id=state_id)
        return state.id

    @Eventful.will_did("load_state", can_raise=False)
    def _load(self, state_id: int) -> StateBase:
        """Load the state from the secondary storage

        :param state_id: a state id
        :returns: the loaded state
        """
        if not hasattr(self, "stcache"):
            self.stcache: weakref.WeakValueDictionary = weakref.WeakValueDictionary()
        if state_id in self.stcache:
            return self.stcache[state_id]
        state = self._workspace.load_state(state_id, delete=False)
        state._id = state_id
        self.forward_events_from(state, True)
        state.manticore = self
        self.stcache[state_id] = state
        return state

    @Eventful.will_did("remove_state", can_raise=False)
    def _remove(self, state_id: int) -> int:
        """Remove a state from secondary storage

        :param state_id: a state id
        """
        if not hasattr(self, "stcache"):
            self.stcache = weakref.WeakValueDictionary()
        if state_id in self.stcache:
            del self.stcache[state_id]

        self._workspace.rm_state(state_id)
        return state_id

    # Internal support for state lists
    def _put_state(self, state) -> int:
        """This enqueues the state for exploration.

        Serialize and store the state with a fresh state_id. Then add it to
        the shared READY states list
        这将使状态排队以进行探索。
        序列化并使用一个新的state_id存储状态。然后将其添加到共享READY状态列表中
                      +-------+
        State +----- >+ READY |
                      +-------+

        """
        state.manticore = self
        self._publish("will_enqueue_state", state, can_raise=False)
        state_id = self._save(state, state_id=state.id)
        with self._lock:
            # Enqueue it in the ready state list for processing
            self._ready_states.append(state_id)
            self._lock.notify_all()
            # The problem with using will_did here is that the lock is released before the event is fired, so typically
            # a worker has moved the state from READY to BUSY *before* `did_enqueue_state` is published.
            #在这里使用will_did的问题是，锁在事件触发之前被释放，所以通常在' did_enqueue_state '被发布之前，工作人员已经将状态从READY *移动到BUSY *。
            self._publish("did_enqueue_state", state_id, can_raise=False)
        return state_id

    def _get_state(self, wait=False) -> typing.Optional[StateBase]:
        """ Dequeue a state form the READY list and add it to the BUSY list从READY列表中取出一个状态，并将其添加到BUSY列表中 """
        with self._lock:
            # If wait is true do the conditional wait for states
            #如果wait为true，则对状态执行条件等待
            if wait:
                # if not more states in the queue, let's wait for some forks
                #如果没有更多的状态在队列中，让我们等待一些分叉
                while not self._ready_states and not self._killed.value:
                    # if a shutdown has been requested then bail
                    if self.is_killed():
                        return None  # Cancelled operation
                    # If there are no more READY states and no more BUSY states
                    # there is no chance we will get any new state so raise如果没有更多的“就绪”状态和“忙碌”状态，我们就没有机会建立新的状态
                    if not self._busy_states:
                        return None  # There are not states

                    # if there ares actually some workers ready, wait for state forks#如果真的有一些工作人员准备好了，那就等着状态分叉吧
                    logger.debug("Waiting for available states")
                    self._lock.wait()

            if self._killed.value:
                return None

            # at this point we know there is at least one element
            # and we have exclusive access此时，我们知道至少有一个元素，并且具有独占访问权
            assert self._ready_states

            # make the choice under exclusive access to the shared ready list
            # state_id = self._policy.choice(list(self._ready_states)[0])在共享就绪列表的独占访问下做出选择state_id = self._policy.choice(list(self._ready_states)[0])
            state_id = random.choice(list(self._ready_states))

            # Move from READY to BUSY
            self._publish("will_transition_state", state_id, StateLists.ready, StateLists.busy)
            self._ready_states.remove(state_id)
            self._busy_states.append(state_id)
            self._publish("did_transition_state", state_id, StateLists.ready, StateLists.busy)
            self._lock.notify_all()

        return self._load(state_id)

    @sync
    def _revive_state(self, state_id: int):
        """Send a state back to READY list

        +--------+        +------------------+
        | READY  +<-------+ BUSY/TERMINATED |
        +---+----+        +----------------+

        """
        # Move from BUSY or TERMINATED to READY
        src = None
        if state_id in self._busy_states:
            src = StateLists.busy
            self._publish("will_transition_state", state_id, src, StateLists.ready)
            self._busy_states.remove(state_id)
        if state_id in self._terminated_states:
            src = StateLists.terminated
            self._publish("will_transition_state", state_id, src, StateLists.ready)
            self._terminated_states.remove(state_id)
        self._ready_states.append(state_id)
        self._publish("did_transition_state", state_id, src, StateLists.ready)
        self._lock.notify_all()

    @sync
    def _terminate_state(self, state_id: int, delete=False):
        """Send a BUSY state to the TERMINATED list or trash it if delete is True
        向TERMINATED列表发送一个BUSY状态，如果delete为True则将其丢弃
        +------+        +------------+
        | BUSY +------->+ TERMINATED |
        +---+--+        +------------+
            |
            v
           ###
           ###

        """
        # wait for a state id to be added to the ready list and remove it
        #等待一个状态id被添加到ready列表并删除它
        if state_id not in self._busy_states:
            raise ManticoreError("Can not terminate. State is not being analyzed")
        self._busy_states.remove(state_id)

        if delete:
            self._remove(state_id)
        else:
            # add the state_id to the terminated list#添加state_id到终止列表
            self._publish("will_transition_state", state_id, StateLists.busy, StateLists.terminated)
            self._terminated_states.append(state_id)
            self._publish("did_transition_state", state_id, StateLists.busy, StateLists.terminated)

        # wake up everyone waiting for a change in the state lists#唤醒所有等待状态列表改变的人
        self._lock.notify_all()

    @sync
    def _kill_state(self, state_id: int, delete=False):
        """Send a BUSY state to the KILLED list or trash it if delete is True向kill列表发送一个BUSY状态，如果delete为True则将其丢弃

        +------+        +--------+
        | BUSY +------->+ KILLED |
        +---+--+        +--------+
            |
            v
           ###
           ###

        """
        # wait for a state id to be added to the ready list and remove it
        #等待一个状态id被添加到ready列表并删除它
        if state_id not in self._busy_states:
            raise ManticoreError("Can not even kill it. State is not being analyzed")
        self._busy_states.remove(state_id)

        if delete:
            self._remove(state_id)
        else:
            # add the state_id to the terminated list
            self._publish("will_transition_state", state_id, StateLists.busy, StateLists.killed)
            self._killed_states.append(state_id)
            self._publish("did_transition_state", state_id, StateLists.busy, StateLists.killed)

        # wake up everyone waiting for a change in the state lists
        self._lock.notify_all()

    @sync
    def kill_state(self, state: typing.Union[StateBase, int], delete: bool = False):
        """Kill a state.
         A state is moved from any list to the kill list or fully
         removed from secondary storage杀死一个状态。将状态从任何列表移到终止列表或从二级存储中完全删除

        :param state: a state
        :param delete: if true remove the state from the secondary storage

        """
        state_id = getattr(state, "id", state)
        src = None
        if state_id in self._busy_states:
            src = StateLists.busy
            self._busy_states.remove(state_id)
        if state_id in self._terminated_states:
            src = StateLists.terminated
            self._terminated_states.remove(state_id)
        if state_id in self._ready_states:
            src = StateLists.ready
            self._ready_states.remove(state_id)

        if delete:
            self._remove(state_id)
        else:
            # add the state_id to the terminated list
            self._publish("will_transition_state", state_id, src, StateLists.killed)
            self._killed_states.append(state_id)
            self._publish("did_transition_state", state_id, src, StateLists.killed)

    @property  # type: ignore
    @sync
    def ready_states(self):
        """
        Iterator over ready states.
        It supports state changes. State changes will be saved back at each iteration.

        The state data change must be done in a loop, e.g. `for state in ready_states: ...`
        as we re-save the state when the generator comes back to the function.

        This means it is not possible to change the state used by Manticore with `states = list(m.ready_states)`.
        迭代器遍历就绪状态。
        它支持状态更改。
        状态更改将在每次迭代时保存回来。
        状态数据的更改必须在循环中完成，例如，' for state in ready_states:。
        当生成器返回函数时，我们重新保存状态。
        这意味着不可能使用' states = list(m.ready_states)来更改Manticore使用的状态。

        """
        _ready_states = self._ready_states
        for state_id in _ready_states:
            state = self._load(state_id)
            yield state
            # Re-save the state in case the user changed its data
            self._save(state, state_id=state_id)

    @property
    def running_states(self):
        logger.warning(
            "manticore.running_states is deprecated! (You probably want manticore.ready_states)"
        )
        return self.ready_states

    @property  # type: ignore
    @sync
    def terminated_states(self):
        """
        Iterates over the terminated states.

        See also `ready_states`.
        """
        for state_id in self._terminated_states:
            state = self._load(state_id)
            yield state
            # Re-save the state in case the user changed its data
            self._save(state, state_id=state_id)

    @property  # type: ignore
    @sync
    @at_not_running
    def killed_states(self):
        """
        Iterates over the cancelled/killed states.

        See also `ready_states`.
        """
        for state_id in self._killed_states:
            state = self._load(state_id)
            yield state
            # Re-save the state in case the user changed its data#重新保存状态，以防用户更改其数据
            self._save(state, state_id=state_id)

    @property  # type: ignore
    @sync
    @at_not_running
    def _all_states(self):
        """Only allowed at not running.非运行状态
        (At running we can have states at busy)运行时状态为busy
        Returns a tuple with all active state ids.返回一个包含所有活动状态id的元组。
        Notably the "killed" states are not included here.
        """
        return tuple(self._ready_states) + tuple(self._terminated_states)

    @property  # type: ignore
    @sync
    def all_states(self):
        """
        Iterates over the all states (ready and terminated)
        It holds a lock so no changes state lists are allowed

        Notably the cancelled states are not included here.

        See also `ready_states`.
        遍历所有状态(就绪和终止)
        它持有一个锁，所以不允许改变状态列表
        值得注意的是，被取消的状态不在这里。
        参见“ready_states”。
        """
        for state_id in self._all_states:
            state = self._load(state_id)
            yield state
            # Re-save the state in case the user changed its data#重新保存状态，以防用户更改其数据
            self._save(state, state_id=state_id)

    @sync
    def count_states(self):
        """ Total states count """
        return len(self._all_states)

    @sync
    def count_all_states(self):
        """ Total states count """
        return self.count_states()

    @sync
    def count_ready_states(self):
        """ Ready states count """
        return len(self._ready_states)

    @sync
    def count_busy_states(self):
        """ Busy states count """
        return len(self._busy_states)

    @sync
    def count_killed_states(self):
        """ Cancelled states count """
        return len(self._killed_states)

    @sync
    def count_terminated_states(self):
        """ Terminated states count """
        return len(self._terminated_states)

    def generate_testcase(self, state, message: str = "test", name: str = "test") -> Testcase:
        if message == "test" and hasattr(state, "_terminated_by") and state._terminated_by:
            message = str(state._terminated_by)
        testcase = self._output.testcase(prefix=name)
        with testcase.open_stream("pkl", binary=True) as statef:
            PickleSerializer().serialize(state, statef)

        # Let the plugins generate a state based report#让插件生成一个基于状态的报告
        for p in self.plugins.values():
            p.generate_testcase(state, testcase, message)

        logger.info("Generated testcase No. %d - %s", testcase.num, message)
        return testcase

    @at_not_running
    def register_plugin(self, plugin: Plugin):
        # Global enumeration of valid events#全局有效事件枚举
        assert isinstance(plugin, Plugin)
        assert plugin.unique_name not in self.plugins, "Plugin instance already registered"
        assert getattr(plugin, "manticore", None) is None, "Plugin instance already owned"

        plugin.manticore = self
        self.plugins[plugin.unique_name] = plugin

        events = Eventful.all_events()
        prefix = Eventful.prefixes
        all_events = [x + y for x, y in itertools.product(prefix, events)]
        for event_name in all_events:
            callback_name = f"{event_name}_callback"
            callback = getattr(plugin, callback_name, None)
            if callback is not None:
                self.subscribe(event_name, callback)

        # Safety checks
        for callback_name in dir(plugin):
            if callback_name.endswith("_callback"):
                event_name = callback_name[:-9]
                if event_name not in all_events:
                    logger.warning(
                        "There is no event named %s for callback on plugin %s",
                        event_name,
                        type(plugin).__name__,
                    )

        for event_name in all_events:
            for plugin_method_name in dir(plugin):
                if event_name in plugin_method_name:
                    if not plugin_method_name.endswith("_callback"):
                        if (
                            plugin_method_name.startswith("on_")
                            or plugin_method_name.startswith("will_")
                            or plugin_method_name.startswith("did_")
                        ):
                            logger.warning(
                                "Plugin methods named '%s()' should end with '_callback' on plugin %s",
                                plugin_method_name,
                                type(plugin).__name__,
                            )
                    if (
                        plugin_method_name.endswith("_callback")
                        and not plugin_method_name.startswith("on_")
                        and not plugin_method_name.startswith("will_")
                        and not plugin_method_name.startswith("did_")
                    ):
                        logger.warning(
                            "Plugin methods named '%s()' should start with 'on_', 'will_' or 'did_' on plugin %s",
                            plugin_method_name,
                            type(plugin).__name__,
                        )

        plugin.on_register()
        return plugin

    @at_not_running
    def unregister_plugin(self, plugin: typing.Union[str, Plugin]):
        """Removes a plugin from manticore.从manticore移除一个插件。之后不应该向它发送事件
        No events should be sent to it after
        """
        if isinstance(plugin, str):  # Passed plugin.unique_name instead of value
            assert plugin in self.plugins, "Plugin instance not registered"
            plugin_inst: Plugin = self.plugins[plugin]
        else:
            plugin_inst = plugin

        assert plugin_inst.unique_name in self.plugins, "Plugin instance not registered"
        plugin_inst.on_unregister()
        del self.plugins[plugin_inst.unique_name]
        plugin_inst.manticore = None

    def subscribe(self, name, callback):
        """ Register a callback to an event"""
        from types import MethodType

        if not isinstance(callback, MethodType):
            callback = MethodType(callback, self)
        super().subscribe(name, callback)

    @property  # type: ignore
    @at_not_running
    def context(self):
        """Convenient access to shared context. We maintain a local copy of the
        share context during the time manticore is not running.
        This local context is copied to the shared context when a run starts
        and copied back when a run finishes
        方便地访问共享上下文。在manticore未运行期间，我们维护共享上下文的本地副本。该本地上下文在运行开始时复制到共享上下文，并在运行结束时复制回来
        """
        return self._shared_context

    @contextmanager
    def locked_context(self, key=None, value_type=list):
        """
        A context manager that provides safe parallel access to the global
        Manticore context. This should be used to access the global Manticore
        context when parallel analysis is activated. Code within the `with` block
        is executed atomically, so access of shared variables should occur within.
        提供对全局Manticore上下文的安全并行访问的上下文管理器。当激活并行分析时，应该使用它来访问全局Manticore上下文。在' with '块中的代码是原子执行的，因此访问共享变量应该发生在。
        Example use::

            with m.locked_context() as context:
                visited['visited'].append(state.cpu.PC)

        Optionally, parameters can specify a key and type for the object paired to this key.::
        可选地，参数可以为与该键配对的对象指定一个键和类型。
            with m.locked_context('feature_list', list) as feature_list:
                feature_list.append(1)

        Note: If standard (non-proxy) list or dict objects are contained in a
        referent, modifications to those mutable values will not be propagated
        through the manager because the proxy has no way of knowing when the
        values contained within are modified. However, storing a value in a
        container proxy (which triggers a __setitem__ on the proxy object) does
        propagate through the manager and so to effectively modify such an item,
        one could re-assign the modified value to the container proxy:
        注意:如果标准(非代理)list或dict对象包含在referent中，对这些可变值的修改将不会通过管理器传播，因为代理无法知道何时修改了其中包含的值。
        然而，在容器代理中存储一个值(在代理对象上触发__setitem__)确实会通过管理器传播，因此为了有效地修改这样的项，可以将修改后的值重新赋给容器代理:
        :param object key: Storage key
        :param value_type: type of value associated with key
        :type value_type: list or dict or set
        """
        with self._lock:
            if key is None:
                # If no key is provided we yield the raw shared context under a lock
                #如果没有提供密钥，我们在一个锁下生成原始共享上下文
                yield self._shared_context
            else:
                # if a key is provided we yield the specific value or a fresh one
                if value_type not in (list, dict):
                    raise TypeError("Type must be list or dict")
                if hasattr(self, "_context_value_types"):
                    value_type = self._context_value_types[value_type]
                context = self._shared_context
                if key not in context:
                    context[key] = value_type()
                yield context[key]

    ############################################################################
    # Public API

    @sync
    def wait(self, condition):
        """ Waits for the condition callable to return True """
        self._lock.wait_for(condition)

    @sync
    def kill(self):
        """Attempt to cancel and kill all the workers.
        Workers must terminate
        RUNNING, STANDBY -> KILLED
        """
        self._publish("will_terminate_execution", self._output)
        self._killed.value = True
        self._lock.notify_all()
        self._publish("did_terminate_execution", self._output)

    def terminate(self):
        logger.warning("manticore.terminate is deprecated (Use manticore.kill)")
        self.kill()

    @sync
    def is_running(self):
        """ True if workers are exploring BUSY states or waiting for READY states """
        # If there are still states in the BUSY list then the STOP/KILL event
        # was not yet answered
        # We know that BUSY states can only decrease after a stop is requested
        return self._running.value

    @sync
    def is_killed(self):
        """ True if workers are killed. It is safe to join them """
        # If there are still states in the BUSY list then the STOP/KILL event
        # was not yet answered
        # We know that BUSY states can only decrease after a kill is requested
        #如果BUSY列表中仍然有状态，那么STOP/KILL事件还没有响应
        #我们知道，BUSY状态只能在请求KILL后减少
        return self._killed.value

    @property
    def workspace(self):
        return self._output.store.uri

    @contextmanager
    def kill_timeout(self, timeout=None):
        """A convenient context manager that will kill a manticore run after
        timeout seconds一个方便的上下文管理器，它将在超时后终止manticore运行
        """
        if timeout is None:
            timeout = consts.timeout

        # Run forever is timeout is negative
        if timeout <= 0:
            try:
                yield
            finally:
                return

        # THINKME kill grabs the lock. Is npt this a deadlock hazard?# THINKME杀手抓住了锁。npt是否存在死锁风险?
        timer = threading.Timer(timeout, self.kill)
        timer.start()

        try:
            yield
        finally:
            timer.cancel()

    @at_not_running
    def run(self):
        """
        Runs analysis.
        """
        # Start measuring the execution time#开始测量执行时间
        with self.locked_context() as context:
            context["time_started"] = time.time()

        # Delete state cache
        # The cached version of a state may get out of sync if a worker in a
        # different process modifies the state删除状态缓存#如果在不同进程中的工作线程修改了某个状态，该状态的缓存版本可能会失去同步
        self.stcache = weakref.WeakValueDictionary()

        # Lazy process start. At the first run() the workers are not forked.
        # This actually starts the worker procs/threads启动懒惰进程。在第一次运行()时，工人没有分叉。
        #实际启动工作进程/线程
        if self.subscribe:
            # User subscription to events is disabled from now on#用户订阅事件从现在开始被禁用
            self.subscribe = None

        self.register_daemon(state_monitor)
        self._daemon_threads[-1].start()  # Start log capture worker

        # Passing generators to callbacks is a bit hairy because the first callback would drain it if we didn't
        # clone the iterator in event.py. We're preserving the old API here, but it's something to avoid in the future.
        # 将生成器传递给回调函数有点麻烦，因为如果我们没有在event.py中克隆迭代器，第一个回调函数就会耗尽它。我们在这里保留了旧的API，但这是将来要避免的。
        self._publish("will_run", self.ready_states)
        self._running.value = True

        # start all the workers!
        for w in self._workers:
            w.start()

        # Create each daemon thread and pass it `self`
        #创建每个守护线程，并传递给它' self '
        for i, cb in enumerate(self._daemon_callbacks):
            if (
                i not in self._daemon_threads
            ):  # Don't recreate the threads if we call run multiple times#如果我们多次调用run，不要重新创建线程
                dt = DaemonThread(
                    id=i, manticore=self
                )  # Potentially duplicated ids with workers. Don't mix!
                self._daemon_threads[dt.id] = dt
                dt.start(cb)

        # Main process. Lets just wait and capture CTRL+C at main#主要过程。让我们等待并捕获主界面的CTRL+C
        with WithKeyboardInterruptAs(self.kill):
            with self._lock:
                while (self._busy_states or self._ready_states) and not self._killed.value:
                    self._lock.wait()

        # Join all the workers!
        for w in self._workers:
            w.join()

        with self._lock:
            assert not self._busy_states and not self._ready_states or self._killed.value

            if self.is_killed():
                logger.debug("Killed. Moving all remaining ready states to killed list")
                # move all READY to KILLED:
                while self._ready_states:
                    state_id = self._ready_states[-1]
                    self._publish(
                        "will_transition_state", state_id, StateLists.ready, StateLists.killed
                    )
                    self._killed_states.append(self._ready_states.pop())
                    self._publish(
                        "did_transition_state", state_id, StateLists.ready, StateLists.killed
                    )

        self._running.value = False
        self._publish("did_run")
        assert not self.is_running()

    @sync
    @at_not_running
    def remove_all(self):
        """
        Deletes all streams from storage and clean state lists从存储中删除所有流并清除状态列表
        """
        for state_id in self._all_states:
            self._remove(state_id)

        del self._ready_states[:]
        del self._busy_states[:]
        del self._terminated_states[:]
        del self._killed_states[:]

    def finalize(self):
        """
        Generate a report testcase for every state in the system and remove
        all temporary files/streams from the workspace为系统中的每个状态生成一个报告测试用例，并从工作区中移除所有临时文件/流
        """
        self.kill()
        for state in self.all_states:
            self.generate_testcase(state)
        self.remove_all()

    def wait_for_log_purge(self):
        """
        If a client has accessed the log server, and there are still buffered logs,
        waits up to 2 seconds for the client to retrieve the logs.
        如果客户端访问了日志服务器，并且仍然有缓冲的日志，则需要等待2秒，以便客户端检索日志。
        """
        if self._daemon_threads[-1].activated:
            for _ in range(8):
                if self._log_queue.empty():
                    break
                time.sleep(0.25)

    ############################################################################
    ############################################################################
    ############################################################################
    ############################################################################
    ############################################################################
    ############################################################################

    def save_run_data(self):
        with self._output.save_stream("command.sh") as f:
            f.write(" ".join(map(shlex.quote, sys.argv)))

        with self._output.save_stream("manticore.yml") as f:
            config.save(f)

        with self._output.save_stream("global.solver_stats") as f:
            for s, n in sorted(SOLVER_STATS.items()):
                f.write("%s: %d\n" % (s, n))

        if SOLVER_STATS["timeout"] > 0 or SOLVER_STATS["unknown"] > 0:
            logger.warning(
                "The SMT solvers returned timeout or unknown for certain program paths. Results could not cover the entire set of possible paths"
            )

        logger.info("Results in %s", self._output.store.uri)

        time_ended = time.time()

        with self.locked_context() as context:
            if "time_started" in context:
                time_elapsed = time_ended - context["time_started"]
                logger.info("Total time: %s", time_elapsed)
                context["time_ended"] = time_ended
                context["time_elapsed"] = time_elapsed
            else:
                logger.warning("Manticore failed to run")

        self.wait_for_log_purge()

    def introspect(self) -> typing.Dict[int, StateDescriptor]:
        """
        Allows callers to view descriptors for each state

        :return: the latest copy of the State Descriptor dict
        """
        key = IntrospectionAPIPlugin.NAME
        if key in self.plugins:
            plug: IntrospectionAPIPlugin = self.plugins[key]  # type: ignore
            return plug.get_state_descriptors()
        return {}

    @at_not_running
    def register_daemon(self, callback: typing.Callable):
        """
        Allows the user to register a function that will be called at `ManticoreBase.run()` and can run
        in the background. Infinite loops are acceptable as it will be killed when Manticore exits. The provided
        function is passed a thread as an argument, with the current Manticore object available as thread.manticore.

        :param callback: function to be called
        """
        self._daemon_callbacks.append(callback)

    def pretty_print_states(self, *_args):
        """ Calls pretty_print_state_descriptors on the current set of state descriptors """
        pretty_print_state_descriptors(self.introspect())
