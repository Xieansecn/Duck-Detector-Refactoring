#include "virtualization/egl_probe.h"

#include <EGL/egl.h>
#include <GLES2/gl2.h>

namespace duckdetector::virtualization {

    RendererSnapshot collect_renderer_snapshot() {
        RendererSnapshot snapshot;

        EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
        if (display == EGL_NO_DISPLAY) {
            return snapshot;
        }
        if (eglInitialize(display, nullptr, nullptr) != EGL_TRUE) {
            return snapshot;
        }

        constexpr EGLint configAttributes[] = {
                EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
                EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
                EGL_RED_SIZE, 8,
                EGL_GREEN_SIZE, 8,
                EGL_BLUE_SIZE, 8,
                EGL_NONE,
        };
        EGLConfig config = nullptr;
        EGLint numConfigs = 0;
        if (eglChooseConfig(display, configAttributes, &config, 1, &numConfigs) != EGL_TRUE ||
            numConfigs <= 0 || config == nullptr) {
            eglTerminate(display);
            return snapshot;
        }

        constexpr EGLint pbufferAttributes[] = {
                EGL_WIDTH, 1,
                EGL_HEIGHT, 1,
                EGL_NONE,
        };
        EGLSurface surface = eglCreatePbufferSurface(display, config, pbufferAttributes);
        if (surface == EGL_NO_SURFACE) {
            eglTerminate(display);
            return snapshot;
        }

        constexpr EGLint contextAttributes[] = {
                EGL_CONTEXT_CLIENT_VERSION, 2,
                EGL_NONE,
        };
        EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, contextAttributes);
        if (context == EGL_NO_CONTEXT) {
            eglDestroySurface(display, surface);
            eglTerminate(display);
            return snapshot;
        }

        if (eglMakeCurrent(display, surface, surface, context) != EGL_TRUE) {
            eglDestroyContext(display, context);
            eglDestroySurface(display, surface);
            eglTerminate(display);
            return snapshot;
        }

        snapshot.available = true;
        const auto *vendor = reinterpret_cast<const char *>(glGetString(GL_VENDOR));
        const auto *renderer = reinterpret_cast<const char *>(glGetString(GL_RENDERER));
        const auto *version = reinterpret_cast<const char *>(glGetString(GL_VERSION));
        if (vendor != nullptr) snapshot.vendor = vendor;
        if (renderer != nullptr) snapshot.renderer = renderer;
        if (version != nullptr) snapshot.version = version;

        eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
        eglDestroyContext(display, context);
        eglDestroySurface(display, surface);
        eglTerminate(display);
        return snapshot;
    }

}  // namespace duckdetector::virtualization
