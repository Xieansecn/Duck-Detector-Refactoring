package com.eltavine.duckdetector.features.virtualization.data.service

import android.content.Context
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteProfile

open class VirtualizationIsolatedProbeManager(
    context: Context? = null,
) : VirtualizationProbeManager(
    context = context,
    serviceClass = VirtualizationIsolatedProbeService::class.java,
    expectedProfile = VirtualizationRemoteProfile.ISOLATED,
)
