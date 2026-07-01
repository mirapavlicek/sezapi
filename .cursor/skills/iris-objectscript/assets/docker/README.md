# Run & verify harness (Docker)

Compiles the HSDemo example inside a real **IRIS for Health Community** instance
and runs its tests. This is what makes the skill "really program": generated code
is proven to compile and pass checks, not just inspected.

## Prerequisites

- Docker Desktop (macOS/Windows) or Docker Engine + Compose v2 on Linux.
- ~4 GB free disk for the image; the first `up` pulls a multi-GB image.
- The image is multi-arch, so it runs on Apple Silicon and x86_64. If your
  platform can't pull it, set `platform: linux/amd64` in `docker-compose.yml`.

## One command

```bash
cd assets/docker
./run.sh
```

`run.sh` will: start IRIS, wait until it accepts sessions, load + compile
everything in `../example-app/src`, run the deterministic smoke gate
(`HSDemo.Tests.Smoke`), then run the `%UnitTest` suite. It prints
`BUILD_RESULT:PASS` and exits 0 only if compilation and all checks succeed;
otherwise it exits non-zero — usable directly in CI.

Expected tail of a successful run:

```
  ok - patient id assigned
  ok - computed FullName
  ok - Python+SQL mean = 72
  ...
BUILD_RESULT:PASS
 BUILD PASSED — code compiled and all checks passed.
```

## Try the REST API

The dispatch class `HSDemo.REST.API` is wired to a web application after you
create one (Management Portal → System Administration → Security → Applications →
Web Applications → New: name `/hsdemo`, Namespace `USER`, Dispatch Class
`HSDemo.REST.API`). Then:

```bash
# create a patient
curl -s -u _SYSTEM:SYS -H 'Content-Type: application/json' \
  -d '{"mrn":"A100","lastName":"Novak","firstName":"Jan","birthDate":"1980-05-01"}' \
  http://localhost:52773/hsdemo/patients

# read it back
curl -s -u _SYSTEM:SYS http://localhost:52773/hsdemo/patients/A100

# add observations, then get the mean (computed in Embedded Python over SQL)
curl -s -u _SYSTEM:SYS -H 'Content-Type: application/json' -d '{"code":"8867-4","value":72}' \
  http://localhost:52773/hsdemo/patients/A100/observations
curl -s -u _SYSTEM:SYS http://localhost:52773/hsdemo/patients/A100/observations/8867-4/mean
```

## Try the interoperability production

Management Portal → Interoperability (choose namespace `USER`) → Configure →
Production → Open `HSDemo.Interop.Production`, Start it, then use the Testing
Service or send an `HSDemo.Interop.PatientMessage` to **Patient File Out**; it
writes a line to `/tmp/patients.txt` in the container.

## Run the %UnitTest suite manually

```objectscript
zn "USER"
set ^UnitTestRoot = "/home/irisowner/src"
do ##class(%UnitTest.Manager).RunTest("HSDemo/Tests","/noload/nodelete/recursive")
```

## Install via IPM instead (optional)

With the IPM/ZPM package manager available:

```objectscript
zpm "load /home/irisowner/src/.. -v"   ; uses ../example-app/module.xml
```

## Teardown

```bash
docker compose down        # stop; keep data
docker compose down -v     # stop and delete the volume/data
```
