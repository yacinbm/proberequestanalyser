"""!
    @file threadUtil.py
    @brief Thread utilities time based tasks.

    @author Yacin Belmihoub-Martel @yacinbm (yacin.belmihoubmartel@gmail.com)
"""
from threading import Timer

class RepeatTimer(Timer):
    """!
    @brief Repeating timer.
    @detailed Repeats a method on a given interval by executing on another thread.
    The task will keep executing until the .cancel() method is called. The RepeatTimer
    class extends the threading.Timer class and is started and declared similarly.
    """
    def run(self):
        while not self.finished.wait(self.interval):
            self.function(*self.args, **self.kwargs)