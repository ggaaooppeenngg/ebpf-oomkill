# ebpf oomkill kprobe

Use 'go generate' to generate ebpf program. Minimal required kernel version is 5.8.

## example

Run `python test.py` and `sudo ebpf-oomkill` which outputs log below.

```
probe
attach done
Waiting for events..
pid: 16541 comm: python
```
