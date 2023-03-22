
# time

## Intro
time - Get the current time in seconds since the Epoch

## Description
The `time` function is a system call which returns the number of seconds that have elapsed since 1970-01-01 00:00:00 UTC ( known as the Epoch). The return value is stored in the timespec pointed to by the argument `tloc`, which must be non-null.

The `time`function is often used for basic performance timing in programs, as the time value can easily be compared to other time values. It is also useful for seed generation for random number generators, since it provides a unique value which is difficult to predict.

However, the time returned by `time` is not necessarily monotonic. It can vary due to a variety of factors, such as discrepancies in hardware clocks, manual updates to the date/time, and daylight saving time adjustments. Therefore, `time` is not suitable for applications which require consistent, monotonic timing.

## Arguments
* `tloc`:`time_t*`[K] - Pointer to timespec structure in which the time should be stored.

### Available Tags
* K - Originated from kernel-space.

## Hooks
### time
#### Type
kprobes
#### Purpose
The `time` function is used to get the current time since the Epoch. Hooking this function allows for monitoring of when the time is requested and may indicate a possible start of an attacker's activities.

## Example Use Case
This event can be used to monitor for suspicious timing in programs. For instance, if a program is consistently requesting the current time, this may indicate that the program is attempting to guess an unpredictable value, such as a seed for a random number generator.

## Issues
None.

## Related Events
* `gettimeofday` - Get the current time in milliseconds since the Epoch.

> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracee recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.