from ..utils.nointerrupt import WithKeyboardInterruptAs
from .state import Concretize, TerminateState
from ..core.plugin import Plugin, StateDescriptor
from .state_pb2 import StateList, MessageList, State, LogMessage
from ..utils.log import register_log_callback
from ..utils import config
from ..utils.enums import StateStatus, StateLists
from datetime import datetime
import logging
import multiprocessing
import threading
from collections import deque
import os
import socketserver
import typing

consts = config.get_group("core")
consts.add("HOST", "localhost", "Address to bind the log & state servers to")
consts.add("PORT", 3214, "Port to use for the log server. State server runs one port higher.")
consts.add(
    "fast_fail",
    False,
    "Kill Manticore if _any_ state encounters an unrecoverable exception/assertion.",
)

logger = logging.getLogger(__name__)
# logger.setLevel(9)


# Workers
# There are 4 types of Workers
# WorkerSingle: run over main process and will not provide any concurrency
# WorkerThread: runs on a different thread
# WorkerProcess: runs on a different process - Full multiprocessing
# WorkerMultiprocessing: --planned-- runs on a different computer
#工人
#有4种类型的工人
# WorkerSingle:运行在主进程上，不提供并发性
# WorkerThread:运行在不同的线程上
# WorkerProcess:运行在不同的进程上-完全多进程
# WorkerMultiprocessing:——planned——在不同的计算机上运行

class Worker:
    """
    A Manticore Worker.
    This will run forever potentially in a different process. Normally it
    will be spawned at Manticore constructor and will stay alive until killed.
    A Worker can be in 3 phases: STANDBY, RUNNING, KILLED. And will react to
    different events: start, stop, kill.
    The events are transmitted via 2 conditional variable: m._killed and
    m._started.
    一个怪兽工人。
    这可能会在不同的进程中永远运行。
    通常它会在蝎尾怪物的构造器中生成，并且在被杀死之前一直存活。
    Worker可以分为3个阶段:STANDBY、RUNNING、KILLED。
    并且会对不同的事件做出反应:开始，停止，杀死。
    事件通过两个条件变量传送:m._killed和m._started。
    .. code-block:: none

        STANDBY:   Waiting for the start event
        RUNNING:   Exploring and spawning states until no more READY states or
        the cancel event is received
        KIlLED:    This is the end. No more manticoring in this worker process

                     +---------+     +---------+
                +--->+ STANDBY +<--->+ RUNNING |
                     +-+-------+     +-------+-+
                       |                     |
                       |      +--------+     |
                       +----->+ KILLED <-----+
                              +----+---+
                                   |
                                   #
    """

    def __init__(self, *, id, manticore, single=False):
        self.manticore = manticore
        self.id = id
        self.single = single

    def start(self):
        raise NotImplementedError

    def join(self):
        raise NotImplementedError

    def run(self, *args):
        # This controls the main symbolic execution loop of one of the workers
        logger.debug(
            "Starting Manticore Symbolic Emulator Worker %d. Pid %d Tid %d).",
            self.id,
            os.getpid(),
            threading.get_ident(),
        )

        m = self.manticore
        current_state = None
        m._publish("will_start_worker", self.id)

        # If CTRL+C is received at any worker lets abort exploration via m.kill()
        # kill will set m._killed flag to true and then each worker will slowly
        # get out of its mainloop and quit.
        #如果在任何工作单位接收到CTRL+C，通过m.kell终止探索。Kill()将设置m._killed标志设置为true，然后每个worker将慢慢退出主循环并退出。
        with WithKeyboardInterruptAs(m.kill):

            # The worker runs until the manticore is killed
            while not m._killed.value:

                # STARTED - Will try to consume states until a STOP event is received
                # Outer loop, Keep getting states until someone request us to STOP
                # STARTED -将尝试消耗状态，直到接收到一个STOP事件外部循环，一直获取状态，直到有人请求我们停止
                try:  # handle fatal errors even exceptions in the exception handlers
                    try:  # handle Concretize and TerminateState

                        # At RUNNING
                        # The START has been requested, we operate with under the assumption
                        # that manticore we will let us stay at this phase for a _while_
                        # Requests to STOP will be honored ASAP (i.e. Not immediately)
                        #在运行START已经被请求，我们在假设manticore的情况下操作，我们将让我们停留在这个阶段_whil_requests to STOP将被尽快执行(即不是立即执行)
                        # Select a single state
                        # wait for other worker to add states to the READY list
                        # This momentarily get the main lock and then releases
                        # it while waiting for changes
                        # Raises an Exception if manticore gets cancelled
                        # while waiting or if there are no more potential states
                        # 这暂时获得主锁，然后在等待更改时释放它。如果在等待时manticore被取消或没有更多的潜在状态
                        logger.debug("[%r] Waiting for states", self.id)
                        # If at STANDBY wait for any change
                        current_state = m._get_state(wait=True)

                        # there are no more states to process
                        # states can come from the ready list or by forking
                        # states currently being analyzed in the busy list
                        # 没有更多的状态来处理，状态可以来自就绪列表或fork当前在繁忙列表中分析的状态
                        if current_state is None:
                            logger.debug("[%r] No more states", self.id)
                            break

                        # assert current_state is not None
                        # Allows to terminate manticore worker on user request
                        # even in the middle of an execution
                        # 允许在用户请求时终止manticore worker，甚至在执行过程中
                        logger.debug("[%r] Running", self.id)
                        assert (
                            current_state.id in m._busy_states
                            and current_state.id not in m._ready_states
                        )

                        # This does not hold the lock so we may loss some event
                        # flickering这并没有保持锁，所以我们可能会丢失一些事件闪烁
                        while not m._killed.value:
                            current_state.execute()
                        else:
                            logger.debug("[%r] Stopped and/or Killed", self.id)
                            # On going execution was stopped or killed. Lets
                            # save any progress on the current state using the
                            # same id. No other worker will use this state in
                            # this run
                            m._save(current_state, state_id=current_state.id)
                            m._revive_state(current_state.id)
                            current_state = None

                        assert current_state is None
                    # Handling Forking and terminating exceptions
                    except Concretize as exc:
                        logger.debug("[%r] Performing %r", self.id, exc.message)
                        # The fork() method can decides which state to keep
                        # exploring. For example when the fork results in a
                        # single state it is better to just keep going.
                        # Though, normally fork() saves the spawned childs,
                        # returns a None and let _get_state choose what to explore
                        # next
                        #fork()方法可以决定继续探索哪个状态。例如，当fork产生单一状态时，最好继续运行。但是，fork()通常保存生成的子节点，返回一个None并让_get_state选择下一步要探索的内容
                        m._fork(current_state, exc.expression, exc.policy, exc.setstate)
                        current_state = None

                    except TerminateState as exc:
                        logger.debug("[%r] Debug State %r %r", self.id, current_state, exc)
                        # Notify this state is done
                        m._publish("will_terminate_state", current_state, exc)
                        # Update the stored version of the current state
                        #更新当前状态的存储版本
                        current_state._terminated_by = exc

                        m._save(current_state, state_id=current_state.id)
                        # Add the state to the terminated state list re-using
                        # the same id. No other worker will use this state in
                        # this run
                        # 使用相同的id将状态添加到终止状态列表中。没有其他工作人员将在此运行中使用此状态
                        m._terminate_state(current_state.id)

                        m._publish("did_terminate_state", current_state, exc)
                        current_state = None

                except (Exception, AssertionError) as exc:
                    import traceback

                    formatted = traceback.format_exc()
                    logger.error("Exception in state %r: %r\n%s ", self.id, exc, formatted)
                    # Internal Exception
                    # Add the state to the terminated state list
                    if current_state is not None:
                        # Drop any work on this state in case it is inconsistent

                        # Update the stored version of the current state
                        # Saved to a fresh id in case other worker have an old
                        # version this state cached over the old id
                        m._publish("will_kill_state", current_state, exc)
                        m._save(current_state, state_id=current_state.id)
                        m._kill_state(current_state.id)
                        m._publish("did_kill_state", current_state, exc)
                        current_state = None
                    if consts.fast_fail:
                        # Kill Manticore if _any_ state encounters unrecoverable
                        # exception/assertion
                        m.kill()
                    break

            # Getting out.
            # At KILLED
            logger.debug("[%r] Getting out of the mainloop", self.id)
            m._publish("did_terminate_worker", self.id)


class WorkerSingle(Worker):
    """A single worker that will run in the current process and current thread.
    As this will not provide any concurrency is normally only used for
    profiling underlying arch emulation and debugging."""
    """将在当前进程和当前线程中运行的单个worker。
    由于这将不提供任何并发性，通常只用于分析底层拱模拟和调试。
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, single=True, **kwargs)

    def start(self):
        self.run()

    def join(self):
        pass


class WorkerThread(Worker):
    """ A worker thread """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._t = None

    def start(self):
        self._t = threading.Thread(target=self.run)
        self._t.start()

    def join(self):
        self._t.join()
        self._t = None


class WorkerProcess(Worker):
    """ A worker process """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._p = None

    def start(self):
        self._p = multiprocessing.Process(target=self.run)
        self._p.start()

    def join(self):
        self._p.join()
        self._p = None


class DaemonThread(WorkerThread):
    """
    Special case of WorkerThread that will exit whenever the main Manticore process exits.
    """

    def start(self, target: typing.Optional[typing.Callable] = None):
        """
        Function that starts the thread. Can take an optional callable to be invoked at the start, or can be subclassed,
        in which case `target` should be None and the the `run` method will be invoked at the start.
        启动线程的函数。可以接受一个可选的可调用对象，以便在开始时调用，或者可以子类化，在这种情况下，' target '应该是None，并且' run '方法将在开始时被调用。
        :param target: an optional callable that will be invoked to start the thread. The callable should accept this
        thread as an argument.
        """
        logger.debug(
            "Starting Daemon %d. (Pid %d Tid %d).",
            self.id,
            os.getpid(),
            threading.get_ident(),
        )

        self._t = threading.Thread(target=self.run if target is None else target, args=(self,))
        self._t.daemon = True
        self._t.start()


class DumpTCPHandler(socketserver.BaseRequestHandler):
    """ TCP Handler that calls the `dump` method bound to the server """

    def handle(self):
        self.request.sendall(self.server.dump())


class ReusableTCPServer(socketserver.TCPServer):
    """ Custom socket server that gracefully allows the address to be reused """

    allow_reuse_address = True
    dump: typing.Optional[typing.Callable] = None


class LogCaptureWorker(DaemonThread):
    """ Extended DaemonThread that runs a TCP server that dumps the captured logs """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.activated = False  #: Whether a client has ever connected
        register_log_callback(self.log_callback)

    def log_callback(self, msg):
        q = self.manticore._log_queue
        try:
            q.append(msg)
        except AttributeError:
            # Appending to a deque with maxlen=n is about 25x faster than checking if a queue.Queue is full,
            # popping if so, and appending. For that reason, we use a deque in the threading and single, but
            # a manager.Queue in multiprocessing (since that's all it supports). Catching an AttributeError
            # is slightly faster than using `isinstance` for the default case (threading) but does slow down
            # log throughput by about 20% (on top of the 25x slowdown) when using Multiprocessing instead of
            # threading
            #将maxlen=n添加到deque中比检查队列是否为队列快大约25倍。队列已满，如果是，弹出，并追加。出于这个原因，我们在线程和单线程中使用了deque，而不是一个管理器。在多处理队列(因为这是它所支持的全部)。捕获AttributeError比在默认情况下(线程)使用' isinstance '稍微快一些，但当使用Multiprocessing而不是线程时，会降低大约20%的日志吞吐量(在25倍的放缓之上)
            if q.full():
                q.get()
            q.put(msg)

    def dump_logs(self):
        """
        Converts captured logs into protobuf format将捕获的日志转换为protobuf格式
        """
        self.activated = True
        serialized = MessageList()
        q = self.manticore._log_queue
        i = 0
        while i < 50 and not q.empty():
            msg = LogMessage(content=q.get())
            serialized.messages.append(msg)
            i += 1
        return serialized.SerializeToString()

    def run(self, *args):
        logger.debug(
            "Capturing Logs via Thread %d. Pid %d Tid %d).",
            self.id,
            os.getpid(),
            threading.get_ident(),
        )

        m = self.manticore

        try:
            with ReusableTCPServer((consts.HOST, consts.PORT), DumpTCPHandler) as server:
                server.dump = self.dump_logs  # type: ignore
                server.serve_forever()
        except OSError as e:
            # TODO - this should be logger.warning, but we need to rewrite several unit tests that depend on
            # specific stdout output in order to do that.
            # 特定的stdout输出，以便完成此操作。
            logger.info("Could not start log capture server: %s", str(e))


def render_state_descriptors(desc: typing.Dict[int, StateDescriptor]):
    """
    Converts the built-in list of state descriptors into a StateList from Protobuf

    :param desc: Output from ManticoreBase.introspect
    :return: Protobuf StateList to send over the wire
    """
    out = StateList()
    for st in desc.values():
        if st.status != StateStatus.destroyed:
            now = datetime.now()
            out.states.append(
                State(
                    id=st.state_id,
                    type={
                        StateLists.ready: State.READY,  # type: ignore
                        StateLists.busy: State.BUSY,  # type: ignore
                        StateLists.terminated: State.TERMINATED,  # type: ignore
                        StateLists.killed: State.KILLED,  # type: ignore
                    }[
                        getattr(st, "state_list", StateLists.killed)
                    ],  # If the state list is missing, assume it's killed
                    reason=st.termination_msg,
                    num_executing=st.own_execs,
                    wait_time=int(
                        (now - st.field_updated_at.get("state_list", now)).total_seconds() * 1000
                    ),
                )
            )
    return out


def state_monitor(self: DaemonThread):
    """
    Daemon thread callback that runs a server that listens for incoming TCP connections and
    dumps the list of state descriptors.
    守护进程线程回调，它运行一个侦听传入TCP连接并转储状态描述符列表的服务器。
    :param self: DeamonThread created to run the server
    """
    logger.debug(
        "Monitoring States via Thread %d. Pid %d Tid %d).",
        self.id,
        os.getpid(),
        threading.get_ident(),
    )

    m = self.manticore

    def dump_states():
        sts = m.introspect()
        sts = render_state_descriptors(sts)
        return sts.SerializeToString()

    try:
        with ReusableTCPServer((consts.HOST, consts.PORT + 1), DumpTCPHandler) as server:
            server.dump = dump_states  # type: ignore
            server.serve_forever()
    except OSError as e:
        # TODO - this should be logger.warning, but we need to rewrite several unit tests that depend on
        # specific stdout output in order to do that.
        logger.info("Could not start state monitor server: %s", str(e))
