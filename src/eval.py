# -*- coding: utf-8 -*-

import cProfile, pstats, io
from memory_profiler import memory_usage


# profiling function
def profile(fnc):
    
    def inner(*args, **kwargs):
        pr = cProfile.Profile()
        pr.enable()
        retval = fnc(*args, **kwargs)
        pr.disable()
        s = io.StringIO()
        sortby = 'cumulative'
        ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
        ps.print_stats()
        print(s.getvalue())
        return retval

    return inner


# profiling function for memory usage
def profile_memory(func):
    def wrapper(*args, **kwargs):
        mem_usage = memory_usage((func, args, kwargs), interval=0.1)
        return max(mem_usage) - min(mem_usage)
    return wrapper
