"""Which repository content ROUTES analyses (shared by the analyzer and the CLI packer)."""

EXCLUDED_DIRS = frozenset({
    "node_modules", ".git", ".hg", ".svn", ".next", ".nuxt", ".turbo", ".vercel", ".netlify", ".cache", ".parcel-cache",
    "dist", "build", "out", "coverage", ".nyc_output", "__pycache__", ".pytest_cache", ".venv", "venv", "vendor",
    ".idea", ".vscode", "bower_components", ".svelte-kit", ".output", ".yarn", "tmp", ".terraform",
})
SKIPPED_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".mp4", ".mov", ".mp3", ".woff", ".woff2",
                    ".ttf", ".otf", ".eot", ".zip", ".gz", ".tgz", ".jar", ".exe", ".dll", ".so", ".dylib", ".bin",
                    ".pdf", ".psd", ".avif", ".wasm", ".node")

# Build-run sources keep images, fonts and other assets the application needs,
# but never prebuilt executables or native modules from the archive.
BUILD_SKIPPED_SUFFIXES = (".exe", ".dll", ".so", ".dylib", ".node", ".jar", ".bin", ".com", ".msi")
BUILD_EXCLUDED_DIRS = frozenset({
    "node_modules", ".git", ".hg", ".svn", ".next", ".nuxt", ".turbo", ".vercel", ".netlify", ".cache", ".parcel-cache",
    "coverage", ".nyc_output", "__pycache__", ".pytest_cache", ".venv", "venv", ".idea", ".vscode", ".yarn",
    ".terraform", ".svelte-kit", ".output",
})
