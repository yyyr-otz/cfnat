name: Build cfnat C (Linux, Windows 11 & Android Termux)

on:
  push:
    tags:
      - "v*"
  workflow_dispatch:
    inputs:
      tag_name:
        description: 'Release 标签版本（例如 v0.0.15，留空则自动从 cfnat.c 提取版本）'
        required: false
        default: ''
      prerelease:
        description: '是否标记为 Pre-release 预发布'
        type: boolean
        default: false

permissions:
  contents: write

jobs:
  build-linux-glibc:
    name: Build ${{ matrix.name }} glibc dynamic
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        include:
          - name: linux-amd64
            artifact: cfnat-linux-amd64
            packages: gcc libc6-dev
            cc: gcc
            cflags: ""
            ldflags: ""
          - name: linux-arm64
            artifact: cfnat-linux-arm64
            packages: gcc-aarch64-linux-gnu libc6-dev-arm64-cross
            cc: aarch64-linux-gnu-gcc
            cflags: ""
            ldflags: ""

    env:
      SOURCE_FILE: cfnat.c

    steps:
      - name: Checkout repository
        uses: actions/checkout@v6
        with:
          fetch-depth: 1
          token: ${{ github.token }}

      - name: Install compiler and tools
        shell: bash
        run: |
          set -euo pipefail
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
            ${{ matrix.packages }} \
            file \
            ca-certificates

      - name: Build Linux glibc dynamic
        shell: bash
        run: |
          set -euo pipefail
          mkdir -p dist

          if [ ! -f "$SOURCE_FILE" ]; then
            echo "SOURCE_FILE '$SOURCE_FILE' not found" >&2
            exit 1
          fi

          ${{ matrix.cc }} \
            -O2 -pipe -std=c11 \
            -Wall -Wextra -Wno-unused-parameter ${{ matrix.cflags }} \
            "$SOURCE_FILE" -o "dist/${{ matrix.artifact }}" \
            -pthread ${{ matrix.ldflags }}

          strip "dist/${{ matrix.artifact }}" || true
          file "dist/${{ matrix.artifact }}"

      - name: Upload artifact
        uses: actions/upload-artifact@v7
        with:
          name: ${{ matrix.artifact }}
          path: dist/${{ matrix.artifact }}
          if-no-files-found: error


  build-linux-musl:
    name: Build ${{ matrix.name }} musl static
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        include:
          - name: linux-amd64-musl
            artifact: cfnat-linux-amd64-musl
            zig_target: x86_64-linux-musl
            cflags: ""
          - name: linux-arm64-musl
            artifact: cfnat-linux-arm64-musl
            zig_target: aarch64-linux-musl
            cflags: ""

    env:
      SOURCE_FILE: cfnat.c
      ZIG_VERSION: 0.15.1

    steps:
      - name: Checkout repository
        uses: actions/checkout@v6
        with:
          fetch-depth: 1
          token: ${{ github.token }}

      - name: Setup Zig
        shell: bash
        run: |
          set -euo pipefail

          case "$(uname -m)" in
            x86_64)
              zig_arch="x86_64"
              ;;
            aarch64|arm64)
              zig_arch="aarch64"
              ;;
            *)
              echo "Unsupported runner arch: $(uname -m)" >&2
              exit 1
              ;;
          esac

          zig_dir="zig-${zig_arch}-linux-${ZIG_VERSION}"
          zig_url="https://ziglang.org/download/${ZIG_VERSION}/${zig_dir}.tar.xz"

          curl -fsSL "$zig_url" -o zig.tar.xz
          tar -xf zig.tar.xz

          echo "$PWD/$zig_dir" >> "$GITHUB_PATH"

      - name: Install common tools
        shell: bash
        run: |
          set -euo pipefail
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
            file \
            ca-certificates

      - name: Build Linux musl static
        shell: bash
        run: |
          set -euo pipefail
          mkdir -p dist

          if [ ! -f "$SOURCE_FILE" ]; then
            echo "SOURCE_FILE '$SOURCE_FILE' not found" >&2
            exit 1
          fi

          zig version

          zig cc -target ${{ matrix.zig_target }} -O2 -pipe -std=c11 \
            -Wall -Wextra -Wno-unused-parameter ${{ matrix.cflags }} \
            "$SOURCE_FILE" -o "dist/${{ matrix.artifact }}" \
            -pthread -static -s

          file "dist/${{ matrix.artifact }}"

      - name: Upload artifact
        uses: actions/upload-artifact@v7
        with:
          name: ${{ matrix.artifact }}
          path: dist/${{ matrix.artifact }}
          if-no-files-found: error


  build-windows:
    name: Build ${{ matrix.name }}
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        include:
          - name: windows-amd64
            artifact: cfnat-windows-amd64.exe
            zig_target: x86_64-windows-gnu
          - name: windows-arm64
            artifact: cfnat-windows-arm64.exe
            zig_target: aarch64-windows-gnu

    env:
      SOURCE_FILE: cfnat.c
      ZIG_VERSION: 0.15.1

    steps:
      - name: Checkout repository
        uses: actions/checkout@v6
        with:
          fetch-depth: 1
          token: ${{ github.token }}

      - name: Setup Zig
        shell: bash
        run: |
          set -euo pipefail

          case "$(uname -m)" in
            x86_64)
              zig_arch="x86_64"
              ;;
            aarch64|arm64)
              zig_arch="aarch64"
              ;;
            *)
              echo "Unsupported runner arch: $(uname -m)" >&2
              exit 1
              ;;
          esac

          zig_dir="zig-${zig_arch}-linux-${ZIG_VERSION}"
          zig_url="https://ziglang.org/download/${ZIG_VERSION}/${zig_dir}.tar.xz"

          curl -fsSL "$zig_url" -o zig.tar.xz
          tar -xf zig.tar.xz

          echo "$PWD/$zig_dir" >> "$GITHUB_PATH"

      - name: Install tools
        shell: bash
        run: |
          set -euo pipefail
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends \
            file \
            ca-certificates

      - name: Build Windows (Win11 amd64 & arm64)
        shell: bash
        run: |
          set -euo pipefail
          mkdir -p dist

          if [ ! -f "$SOURCE_FILE" ]; then
            echo "SOURCE_FILE '$SOURCE_FILE' not found" >&2
            exit 1
          fi

          zig cc -target ${{ matrix.zig_target }} \
            -O2 -pipe -std=c11 -D_WIN32_WINNT=0x0A00 \
            -finput-charset=UTF-8 -fexec-charset=UTF-8 \
            -Wall -Wextra -Wno-unused-parameter \
            "$SOURCE_FILE" -o "dist/${{ matrix.artifact }}" \
            -lws2_32 -ldnsapi -lwininet -static -s

          file "dist/${{ matrix.artifact }}"

      - name: Upload artifact
        uses: actions/upload-artifact@v7
        with:
          name: ${{ matrix.artifact }}
          path: dist/${{ matrix.artifact }}
          if-no-files-found: error


  build-android:
    name: Build ${{ matrix.name }} (Android NDK Termux)
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        include:
          - name: android-arm64
            artifact: cfnat-android-arm64
            target: aarch64-linux-android
            api: 24
          - name: android-amd64
            artifact: cfnat-android-amd64
            target: x86_64-linux-android
            api: 24

    env:
      SOURCE_FILE: cfnat.c
      NDK_VERSION: "26.1.10909125"

    steps:
      - name: Checkout repository
        uses: actions/checkout@v6
        with:
          fetch-depth: 1
          token: ${{ github.token }}

      - name: Setup Android NDK
        uses: nttld/setup-ndk@v1
        with:
          ndk-version: r26b
          add-to-path: true

      - name: Build Android Termux binary
        shell: bash
        run: |
          set -euo pipefail
          mkdir -p dist

          if [ ! -f "$SOURCE_FILE" ]; then
            echo "SOURCE_FILE '$SOURCE_FILE' not found" >&2
            exit 1
          fi

          CC="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin/${{ matrix.target }}${{ matrix.api }}-clang"
          STRIP="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"

          "$CC" \
            -O2 -pipe -std=c11 -Wall -Wextra -Wno-unused-parameter \
            -D__ANDROID__ \
            "$SOURCE_FILE" -o "dist/${{ matrix.artifact }}" \
            -pthread

          "$STRIP" "dist/${{ matrix.artifact }}"
          file "dist/${{ matrix.artifact }}"

      - name: Upload artifact
        uses: actions/upload-artifact@v7
        with:
          name: ${{ matrix.artifact }}
          path: dist/${{ matrix.artifact }}
          if-no-files-found: error


  release:
    name: Publish release
    needs:
      - build-linux-glibc
      - build-linux-musl
      - build-windows
      - build-android
    runs-on: ubuntu-latest
    if: startsWith(github.ref, 'refs/tags/') || github.event_name == 'workflow_dispatch'

    steps:
      - name: Checkout repository
        uses: actions/checkout@v6
        with:
          fetch-depth: 1
          token: ${{ github.token }}

      - name: Determine tag name
        id: vars
        shell: bash
        run: |
          set -euo pipefail
          if [[ "${{ github.ref }}" == refs/tags/* ]]; then
            tag="${GITHUB_REF#refs/tags/}"
          elif [ -n "${{ inputs.tag_name }}" ]; then
            tag="${{ inputs.tag_name }}"
          else
            # 从 cfnat.c 自动提取 CFNAT_VERSION
            ver=$(grep -E '^#define[[:space:]]+CFNAT_VERSION[[:space:]]+"' cfnat.c | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')
            if [ -n "$ver" ]; then
              tag="v${ver}"
            else
              tag="continuous"
            fi
          fi
          echo "tag=$tag" >> "$GITHUB_OUTPUT"
          echo "Using release tag: $tag"

      - name: Download artifacts
        uses: actions/download-artifact@v8
        with:
          path: dist

      - name: Assemble release files
        shell: bash
        run: |
          set -euo pipefail

          mkdir -p release

          find dist -maxdepth 3 -type f -print0 | while IFS= read -r -d '' file; do
            name="$(basename "$file")"
            cp "$file" "release/$name"
          done

          echo "Release contents:"
          find release -maxdepth 1 -type f -exec ls -lh {} \;

      - name: Create checksums
        shell: bash
        run: |
          set -euo pipefail

          cd release
          sha256sum * > sha256sums.txt

      - name: Upload GitHub Release
        uses: softprops/action-gh-release@v3
        with:
          tag_name: ${{ steps.vars.outputs.tag }}
          name: Release ${{ steps.vars.outputs.tag }}
          prerelease: ${{ inputs.prerelease || false }}
          make_latest: true
          files: release/*
