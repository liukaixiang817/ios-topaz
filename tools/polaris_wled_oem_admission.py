"""Independent admission for one no-OS Polaris WLED cycle, never installation.

Pure scope checks are followed by file/binary/source/raw-memory verification
in the packager. Diagnostic/VM success alone is not physical power evidence.
"""
BASE_CHECKS={'firmware_EL1_admission','exact_payload_valid','kernel_prepared_not_executed',
 'no_PSCI_CPU_ON','mock_backend_explicit','preflight_succeeded','expected_final_error',
 'expected_final_uncertainty','writes_issued_exactly','writes_completed_exactly','reset_gate',
 'off_readback_and_reset','on_readback_after_two_seconds','actual_AP_context_stage_zero',
 'actual_kernel_log_total_zero','no_native_startup_log','no_panic'}
VECTORS={(False,None,0),(True,None,0),(False,'owner',0),(False,'configuration',0),(False,'before-cycle',0),
         (False,None,2),(False,None,4),(False,None,128),
         (False,None,512),(False,None,1024),(False,None,32768)}
PHYSICAL_SCOPE=dict(WLED_power_cycle_only=True,WLED_OEM_status_policy=True,
 WLED_OEM_physical_cycle=True,WLED_readonly_inventory_only=False,
 kernel_CPU_ON_compiled_out=True,kernel_handoff=False,PMIC_write_api=True,
 storage_write_api=False,NVRAM_write_api=False,probe_only=True,holds_before_OS_start=True,
 physical_buttons=True,ready_to_boot_driver=True,QEMU_variant=False,phone_compatible=True,
 kernel_CPU_affinity=1792,kernel_CPU_count=4,selected_application=False,disk_payload_read_only=False,
 physical_owned_marker_test=False,controlled_WLED_write_timeout=False,controlled_WLED_prepare_refusal=False,
 controlled_WLED_read_refusal=False,controlled_WLED_fault_pulse=False,WLED_readonly_fault_watch=False,
 controlled_WLED_status_after_issue=0,RAM_host_idle_recovery_seconds=1800,
 WLED_journal_version=2,WLED_journal_bytes_max=1348,WLED_final_reset_receipt_bytes=56,WLED_zero_write_receipt_bytes=16,
 payload_C_admission=True,rebased_kernel_bytes_match=True)
PHYSICAL_SCOPE.update(RAM_only_XNU_loader=True,physical_small_file_write_test=False)
PHYSICAL_SCOPE['controlled_WLED_prepare_kind']=None


def exact_scope(driver):
    for key,value in PHYSICAL_SCOPE.items():
        if key not in driver or type(driver.get(key)) is not type(value) or driver[key]!=value:
            raise ValueError('not the independent physical OEM WLED scope: '+key)
    if driver.get('chain_app') is not None or not driver.get('inputs'):
        raise ValueError('foreign chain or missing exact source inputs')


def vector(model):
    values=(model.get('controlled_write_timeout'),model.get('controlled_prepare_kind'),model.get('controlled_status_after_issue'))
    if (type(values[0]) is not bool or model.get('controlled_prepare_refusal') is not (values[1] is not None) or
        type(values[2]) is not int or values not in VECTORS):
        raise ValueError('unknown or combined WLED fault vector')
    return values


def admit(driver,models):
    exact_scope(driver)
    if len(models)!=len(VECTORS):raise ValueError('all eleven independent OEM EFI cases required')
    seen=set()
    for m in models:
        v=vector(m);timeout,prepare,status=v
        if v in seen:raise ValueError('duplicate WLED case cannot replace a missing refusal')
        seen.add(v)
        if (m.get('passed') is not True or m.get('WLED_OEM_status_policy') is not True or
            m.get('WLED_power_cycle_only') is not True or m.get('inputs')!=driver['inputs'] or
            m.get('kernel_sha256')!=driver.get('kernel_sha256') or
            m.get('kernel_CPU_started') is not False or m.get('release_handoff_admitted') is not False or
            m.get('actual_phone_or_PMIC_emulated') is not False or m.get('physical_PMIC_power_control_tested') is not False):
            raise ValueError('missing or stale actual EFI no-CPU evidence')
        checks=BASE_CHECKS|{'OEM_policy_explicit','retained_status_history','actual_binary_journal'}
        if prepare=='before-cycle':checks=(checks-{'OEM_policy_explicit'})|{'OEM_scope_compiled_but_not_entered'}
        if prepare:
            checks=(checks-{'preflight_succeeded'})|{'preflight_refused_without_write',
                    'before_cycle_no_WLED_access' if prepare=='before-cycle' else 'source_status_retained_before_refusal',
                    'actual_zero_write_recovery_receipt'}
        elif status:checks|={'serious_word_retained','no_false_final_receipt'}
        elif timeout:checks|={'ILIM_history_not_discarded','no_false_final_receipt'}
        else:checks|={'ILIM_history_not_discarded','final_two_actual_reset_reads'}
        if set(m.get('checks',{}))!=checks or any(x is not True for x in m['checks'].values()):
            raise ValueError('missing actual reset/readback/raw-history check')
        raw=m.get('raw_fields',{});journal=m.get('binary_journal_evidence',{}).get('journal',{})
        error={'owner':32,'configuration':33,'before-cycle':0}.get(prepare,65 if status else 36 if timeout else 0)
        issued=0 if prepare else 1 if (timeout or status) else 4
        completed=0 if (prepare or timeout) else issued
        if (raw.get('WLED_POWER_MOCK_BACKEND')!=1 or raw.get('WLED_KERNEL_AP_STAGE')!=0 or
            raw.get('WLED_POWER_FINAL_ERROR')!=error or raw.get('WLED_POWER_FINAL_UNCERTAIN')!=int(bool(timeout or status)) or
            raw.get('WLED_POWER_FINAL_RESET_ALLOWED')!=int(not(timeout or status)) or
            journal.get('error')!=error or journal.get('issued')!=issued or journal.get('completed')!=completed):
            raise ValueError('actual command/uncertainty/error/reset result mismatch')
        if prepare:
            if (journal.get('count')!=0 or journal.get('cycle_restored_readbacks') is not False or
                m.get('binary_journal_evidence',{}).get('zero_write_receipt',{}).get('no_PMIC_command_issued_receipt') is not True):
                raise ValueError('zero-write refusal is not a restored power cycle')
        elif timeout or status:
            if journal.get('cycle_restored_readbacks') is not False or raw.get('WLED_RESET_RECEIPT_READY')!=0:
                raise ValueError('failed cycle falsely admits final reset')
        elif (journal.get('cycle_restored_readbacks') is not True or
              m.get('binary_journal_evidence',{}).get('final_receipt',{}).get('final_restore_receipt_valid') is not True):
            raise ValueError('final two live readbacks absent')
    if seen!=VECTORS:raise ValueError('incomplete WLED fault matrix')
