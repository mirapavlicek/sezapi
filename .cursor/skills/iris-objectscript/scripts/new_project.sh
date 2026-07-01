#!/usr/bin/env bash
# Scaffold a new InterSystems IRIS project: source tree, a starter persistent
# class + unit test (from assets/templates), an IPM module.xml, and a copy of the
# Docker run/test harness wired to the new src directory.
#
# Usage:  ./new_project.sh <target-dir> <RootPackage>
# Example: ./new_project.sh ~/work/myapp Acme.MyApp
set -euo pipefail

TARGET="${1:?usage: new_project.sh <target-dir> <RootPackage>}"
PKG="${2:?usage: new_project.sh <target-dir> <RootPackage>}"

SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TPL="$SKILL_DIR/assets/templates"
DOCKER="$SKILL_DIR/assets/docker"

PKG_PATH="${PKG//.//}"          # dots -> slashes for the filesystem
SRC="$TARGET/src/$PKG_PATH"

mkdir -p "$SRC/Tests" "$TARGET/docker"

subst() {  # subst <template> <class> <desc> <out>
  sed -e "s/__PKG__/$PKG/g" \
      -e "s/__CLASS__/$2/g" \
      -e "s/__DESC__/$3/g" \
      -e "s|__PKG_PATH__|$PKG_PATH/Tests|g" \
      "$1" > "$4"
}

subst "$TPL/persistent-class.cls" "Sample" "Starter persistent class." "$SRC/Sample.cls"

# Test class lives in the .Tests sub-package so its name matches its path.
sed -e "s/__PKG__/$PKG.Tests/g" \
    -e "s/__CLASS__/SampleTest/g" \
    -e "s/__DESC__/Starter unit test./g" \
    -e "s|__PKG_PATH__|$PKG_PATH/Tests|g" \
    "$TPL/unit-test.cls" > "$SRC/Tests/SampleTest.cls"

# IPM manifest
cat > "$TARGET/module.xml" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<Export generator="IRIS" version="26">
  <Document name="$(echo "$PKG" | tr 'A-Z.' 'a-z-').ZPM">
    <Module>
      <Name>$(echo "$PKG" | tr 'A-Z.' 'a-z-')</Name>
      <Version>0.1.0</Version>
      <Packaging>module</Packaging>
      <SourcesRoot>src</SourcesRoot>
      <Resource Name="${PKG}.PKG"/>
    </Module>
  </Document>
</Export>
XML

# Docker harness, with the compile target pointed at this project's src.
cp "$DOCKER/run.sh" "$TARGET/docker/run.sh"
chmod +x "$TARGET/docker/run.sh"
# Compile-gated load/test script for the new project (compile success = gate;
# the %UnitTest run is informational and cannot break the gate).
cat > "$TARGET/docker/load_and_test.script" <<SCRIPT
zn "USER"
write !,"== Loading and compiling /home/irisowner/src ==",!
set lsc = \$System.OBJ.LoadDir("/home/irisowner/src","ck",.err,1)
do \$System.OBJ.DisplayError(lsc)
if \$System.Status.IsError(lsc) { write !,"BUILD_RESULT:FAIL",! halt }
write !,"== %UnitTest suite (informational) ==",!
set ^UnitTestRoot = "/home/irisowner/src"
try { do ##class(%UnitTest.Manager).RunTest("$PKG_PATH/Tests","/noload/nodelete/recursive") } catch ex { write !,"(unit test skipped: ",ex.DisplayString(),")",! }
write !,"BUILD_RESULT:PASS",!
halt
SCRIPT
cat > "$TARGET/docker/docker-compose.yml" <<YML
services:
  iris:
    image: intersystemsdc/irishealth-community:latest
    container_name: $(basename "$TARGET")-iris
    init: true
    ports:
      - "1972:1972"
      - "52773:52773"
    volumes:
      - ./../src:/home/irisowner/src:ro
      - ./load_and_test.script:/home/irisowner/load_and_test.script:ro
YML

echo "Scaffolded $PKG in $TARGET"
echo "  source:  $SRC"
echo "  run:     (cd '$TARGET/docker' && ./run.sh)"
