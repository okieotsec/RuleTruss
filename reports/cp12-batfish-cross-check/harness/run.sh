#!/bin/bash
# runs in the container: Batfish service only (no Jupyter), then the harness
cd / 
java -XX:-UseCompressedOops -XX:+UseContainerSupport -XX:MaxRAMPercentage=70 -Dlog4j.configurationFile=log4j2.yaml \
  -cp allinone-bundle.jar org.batfish.allinone.Main -runclient false -loglevel warn \
  -coordinatorargs "-templatedirs questions -containerslocation /data/containers" > /out/batfish.log 2>&1 &
timeout 600 python3 /in/run_bf.py > /out/harness.log 2>&1
rc=$?
kill %1 2>/dev/null
exit $rc
