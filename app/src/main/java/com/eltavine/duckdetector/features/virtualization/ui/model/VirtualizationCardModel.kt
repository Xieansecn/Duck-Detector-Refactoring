package com.eltavine.duckdetector.features.virtualization.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class VirtualizationCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<VirtualizationHeaderFactModel>,
    val environmentRows: List<VirtualizationDetailRowModel>,
    val runtimeRows: List<VirtualizationDetailRowModel>,
    val consistencyRows: List<VirtualizationDetailRowModel>,
    val honeypotRows: List<VirtualizationDetailRowModel>,
    val hostAppRows: List<VirtualizationDetailRowModel>,
    val impactItems: List<VirtualizationImpactItemModel>,
    val methodRows: List<VirtualizationDetailRowModel>,
    val scanRows: List<VirtualizationDetailRowModel>,
    val references: List<String>,
)

data class VirtualizationHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class VirtualizationDetailRowModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class VirtualizationImpactItemModel(
    val text: String,
    val status: DetectorStatus,
)
