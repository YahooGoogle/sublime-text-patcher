"""Optional development check, NEVER used by the normal offline patcher.

Requires frida and two separate portable directories containing Data/ and
sublime_text.exe plus its normal dependencies. Operates only on child PIDs.
"""
import argparse
import json
from pathlib import Path
import subprocess
import time

import sublime_patch as sp
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP


def metadata(data):
    image, patches, _ = sp.analyze(data)
    purchase, update = patches
    fn = image.containing(purchase.rva)
    insns = image.instructions(fn)
    counter = sp.unique([sp.rip_target(i) for i in insns if i.mnemonic == 'inc'
                         and sp.rip_target(i) is not None], 'runtime counter')
    subtract = sp.unique([i for i in insns if i.mnemonic == 'sub' and sp.rip_target(i) is not None],
                         'runtime timestamp subtraction')
    clock = [i for i in insns if i.mnemonic == 'call' and sp.immediate(i) is not None
             and i.address < subtract.address][-1]
    elapsed = next(i for i in insns if i.address > subtract.address and i.mnemonic == 'cmp'
                   and i.operands[-1].type == X86_OP_IMM)
    enable = sp.unique([i for i in insns[:6] if i.mnemonic == 'cmp'
                        and i.operands[0].type == X86_OP_MEM and i.operands[0].mem.base != X86_REG_RIP
                        and i.operands[1].type == X86_OP_IMM and i.operands[1].imm == 0], 'runtime object flag')
    attempts = max(i.operands[1].imm for i in insns if i.mnemonic == 'cmp'
                   and i.operands[0].type == X86_OP_REG and i.operands[0].size == 4
                   and i.operands[1].type == X86_OP_IMM)
    ufn = image.containing(update.rva)
    uins = image.instructions(ufn)
    first_after_gate = update.evidence['first_body_instruction_rva']
    busy = next(i for i in uins if i.address >= first_after_gate and i.mnemonic == 'cmp'
                and sp.rip_target(i) is not None and i.operands[0].size == 1
                and i.operands[1].type == X86_OP_IMM and i.operands[1].imm == 0)
    return dict(purchase_function=fn.start, dispatch=purchase.evidence['dispatch_rva'],
                counter=counter, timestamp=sp.rip_target(subtract), clock=sp.immediate(clock),
                interval=elapsed.operands[1].imm, attempts=attempts,
                object_flag=enable.operands[0].mem.disp,
                update_function=ufn.start, update_switch=update.evidence['config_switch_rva'],
                busy_flag=sp.rip_target(busy), after_update_gate=first_after_gate,
                expected_purchase=int(purchase.status == 'needs_patch'),
                expected_update=int(update.status == 'needs_patch'))


JS = r"""
const cfg = CONFIG;
const base = Process.getModuleByName('sublime_text.exe').base;
let scheduled=0, passed=0, updateEntry=0, updateReturn=0;
// Replace only the reminder dispatch in this disposable child. The probe can
// observe scheduling without displaying a modal or touching user state.
const noReminder = new NativeCallback(function(a,b,c){ scheduled++; },
    'void',['pointer','pointer','pointer']);
Interceptor.replace(base.add(cfg.dispatch),noReminder);
Interceptor.attach(base.add(cfg.after_update_gate),{onEnter(){passed++;}});
Interceptor.attach(base.add(cfg.update_function),{
    onEnter(){updateEntry++;},onLeave(){updateReturn++;}
});
rpc.exports={probe(){
    const before={scheduled,passed,updateEntry,updateReturn};
    const state=Memory.alloc(64);
    state.add(cfg.object_flag).writeU8(0);
    const oldCounter=base.add(cfg.counter).readU32();
    const oldTimestamp=base.add(cfg.timestamp).readS64();
    const oldSwitch=base.add(cfg.update_switch).readU8();
    const oldBusy=base.add(cfg.busy_flag).readU8();
    try {
        const clock=new NativeFunction(base.add(cfg.clock),'int64',[]);
        base.add(cfg.counter).writeU32(cfg.attempts);
        base.add(cfg.timestamp).writeS64(clock().sub(cfg.interval+1000));
        new NativeFunction(base.add(cfg.purchase_function),'void',['pointer'])(state);
        // Same conditions in both groups: first gate is enabled, second busy
        // gate blocks all actual network work in the baseline.
        base.add(cfg.update_switch).writeU8(1);
        base.add(cfg.busy_flag).writeU8(1);
        new NativeFunction(base.add(cfg.update_function),'void',
            ['pointer','pointer','pointer','pointer'])(ptr(0),ptr(0),ptr(0),ptr(0));
        return {originalUpdateSwitch:oldSwitch,forcedUpdateSwitch:1,
            purchaseScheduled:scheduled-before.scheduled,
            updatePassedGate:passed-before.passed,
            updateEntered:updateEntry-before.updateEntry,
            updateReturned:updateReturn-before.updateReturn};
    } finally {
        base.add(cfg.counter).writeU32(oldCounter);
        base.add(cfg.timestamp).writeS64(oldTimestamp);
        base.add(cfg.update_switch).writeU8(oldSwitch);
        base.add(cfg.busy_flag).writeU8(oldBusy);
    }
}};
"""


def portable_path(directory):
    directory = directory.resolve()
    if not (directory / 'Data').is_dir():
        raise sp.PatchError('Runtime checks require a disposable portable directory containing Data/.')
    exe = directory / 'sublime_text.exe'
    if not exe.is_file():
        raise sp.PatchError(f'Missing {exe}')
    sp.require_stopped(exe)
    return exe


def probe(exe, expected_state):
    import frida
    cfg = metadata(exe.read_bytes())
    if (cfg['expected_purchase'], cfg['expected_update']) != expected_state:
        raise sp.PatchError('Unexpected baseline/candidate patch states for runtime verification.')
    device = frida.get_local_device()
    pid = device.spawn([str(exe), '--multiinstance', '--safe-mode', '--new-window'])
    session = None
    try:
        session = device.attach(pid)
        script = session.create_script(JS.replace('CONFIG', json.dumps(cfg)))
        errors = []
        script.on('message', lambda m, d: errors.append(m) if m['type'] == 'error' else None)
        script.load()
        device.resume(pid)
        time.sleep(3)
        result = script.exports_sync.probe()
        assert not errors, errors
        assert result['purchaseScheduled'] == expected_state[0], result
        assert result['updatePassedGate'] == expected_state[1], result
        assert result['updateEntered'] == result['updateReturned'] == 1, result
        return dict(executable=str(exe), sha256=sp.digest(exe.read_bytes()), config=cfg, observations=result)
    finally:
        try:
            device.kill(pid)
        except Exception:
            pass
        if session:
            try:
                session.detach()
            except Exception:
                pass


def smoke(exe):
    result = []
    for n in (1, 2):
        child = subprocess.Popen([str(exe), '--multiinstance', '--safe-mode', '--new-window'])
        try:
            time.sleep(4)
            assert child.poll() is None, f'Cold start {n} exited with {child.returncode}'
            result.append(dict(run=n, pid=child.pid, alive=True))
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=10)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-directory', type=Path, required=True)
    parser.add_argument('--candidate-directory', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    baseline = portable_path(args.baseline_directory)
    candidate = portable_path(args.candidate_directory)
    if baseline == candidate:
        raise sp.PatchError('Baseline and candidate must be different portable directories.')
    if args.report.exists():
        raise sp.PatchError('Report already exists; select a new filename.')
    result = {'baseline': probe(baseline, (1, 1)), 'candidate': probe(candidate, (0, 0)),
              'cold_starts_without_instrumentation': smoke(candidate)}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    sp.write_new(args.report, (json.dumps(result, ensure_ascii=False, indent=2) + '\n').encode())
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
