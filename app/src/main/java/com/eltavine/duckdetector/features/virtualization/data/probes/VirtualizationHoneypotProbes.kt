package com.eltavine.duckdetector.features.virtualization.data.probes

import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationNativeBridge
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationTrapResult

open class NativeTimingTrapProbe(
    private val nativeBridge: VirtualizationNativeBridge = VirtualizationNativeBridge(),
) {
    open fun probe(): VirtualizationTrapResult = nativeBridge.runTimingTrap()
}

open class NativeSyscallParityTrapProbe(
    private val nativeBridge: VirtualizationNativeBridge = VirtualizationNativeBridge(),
) {
    open fun probe(): VirtualizationTrapResult = nativeBridge.runSyscallParityTrap()
}

open class AsmCounterTrapProbe(
    private val nativeBridge: VirtualizationNativeBridge = VirtualizationNativeBridge(),
) {
    open fun probe(): VirtualizationTrapResult = nativeBridge.runAsmCounterTrap()
}

open class AsmRawSyscallTrapProbe(
    private val nativeBridge: VirtualizationNativeBridge = VirtualizationNativeBridge(),
) {
    open fun probe(): VirtualizationTrapResult = nativeBridge.runAsmRawSyscallTrap()
}
