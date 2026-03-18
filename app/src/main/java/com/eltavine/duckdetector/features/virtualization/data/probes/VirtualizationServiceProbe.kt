package com.eltavine.duckdetector.features.virtualization.data.probes

import android.os.IBinder
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignal
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalGroup
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity

data class VirtualizationServiceProbeResult(
    val listedServiceCount: Int,
    val signals: List<VirtualizationSignal>,
)

open class VirtualizationServiceProbe {

    @Suppress("PrivateApi")
    open fun probe(): VirtualizationServiceProbeResult {
        return runCatching {
            val serviceManagerClass = Class.forName("android.os.ServiceManager")
            val getServiceMethod = serviceManagerClass.getMethod("getService", String::class.java)
            val listServicesMethod = serviceManagerClass.getMethod("listServices")
            val listedServices = (listServicesMethod.invoke(null) as? Array<*>)
                ?.filterIsInstance<String>()
                .orEmpty()

            val signals = mutableListOf<VirtualizationSignal>()
            val qemudBinder = getServiceMethod.invoke(null, "qemud") as? IBinder
            if (qemudBinder != null || listedServices.any {
                    it.equals(
                        "qemud",
                        ignoreCase = true
                    )
                }) {
                signals += VirtualizationSignal(
                    id = "virt_service_qemud",
                    label = "qemud service",
                    value = "Present",
                    group = VirtualizationSignalGroup.RUNTIME,
                    severity = VirtualizationSignalSeverity.DANGER,
                    detail = "ServiceManager exposed qemud, which is a direct emulator guest service.",
                )
            }

            val virtualizationService = getServiceMethod.invoke(
                null,
                "android.system.virtualizationservice",
            ) as? IBinder
            if (
                virtualizationService != null ||
                listedServices.any { it.contains("virtualizationservice", ignoreCase = true) }
            ) {
                signals += VirtualizationSignal(
                    id = "virt_service_virtualizationservice",
                    label = "VirtualizationService",
                    value = "Present",
                    group = VirtualizationSignalGroup.ENVIRONMENT,
                    severity = VirtualizationSignalSeverity.INFO,
                    detail = "Capability-only service. It does not imply the current process is inside a guest.",
                )
            }

            VirtualizationServiceProbeResult(
                listedServiceCount = listedServices.size,
                signals = signals,
            )
        }.getOrDefault(VirtualizationServiceProbeResult(0, emptyList()))
    }
}
