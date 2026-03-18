package com.eltavine.duckdetector.features.virtualization.data.service

import android.os.IBinder

object VirtualizationProbeProtocol {
    const val DESCRIPTOR = "com.eltavine.duckdetector.features.virtualization.probe"
    const val TRANSACTION_COLLECT_SNAPSHOT = IBinder.FIRST_CALL_TRANSACTION + 0
    const val TRANSACTION_IS_NATIVE_AVAILABLE = IBinder.FIRST_CALL_TRANSACTION + 1
    const val TRANSACTION_RUN_SACRIFICIAL_SYSCALL_PACK = IBinder.FIRST_CALL_TRANSACTION + 2
    const val LIST_SEPARATOR = "\u001f"
}
