#pragma once

#include <string>

namespace duckdetector::virtualization {

    struct RendererSnapshot {
        bool available = false;
        std::string vendor;
        std::string renderer;
        std::string version;
    };

    RendererSnapshot collect_renderer_snapshot();

}  // namespace duckdetector::virtualization
