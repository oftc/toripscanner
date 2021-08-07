#!/usr/bin/env bash
# Generate a new list of current exit IPs.
#
# Provide two arguments:
#
#    1. The scan results directory, in which results.log resides as well as its
#    older logrotated siblings, if any.
#
#    2. The output directory, in which we create a file with the current
#    timestamp, output the list, and update a static symlink to the new
#    timestamped file.
#
# We "rotate" older output lists. Files newer than 1 day old are left alone.
# Between 1 day and 30 days old, files are compressed. Older than 30 days,
# files are deleted.
#
# Example invocation:
#
#    $ ./contrib/iplist-rotate.sh /data/scan/results /output/directory
#
# This looks for results.log, results.log.1.gz, results.log.2.gz, etc. inside
# /data/scan/results. It then outputs results to
# /output/directory/exitips.<current_ts>.txt and creates/updates the symbolic
# link /output/directory/exitips.txt to point to
# /output/directory/exitips.<current_ts>.txt.
set -eu
resultsdir="$1"
outdir="$2"
now=$(date +'%s')
outfile=$outdir/exitips.$now.txt
symlink=$outdir/exitips.txt

function finish {
    # A previous version of this script had temporary files to clean up. This
    # useless function is left here as a reminder of how to easily and reliably
    # clean up, even after an error.
    echo ''
}
trap finish EXIT

toripscanner -c config.ini parse \
    $resultsdir/results.log* \
    > "$outfile"

ln -vs "$outfile" "${symlink}.tmp"
mv -vf "${symlink}.tmp" "${symlink}"

find "$outdir" -type f -mtime +1 | xargs --no-run-if-empty gzip -v || echo $?
find "$outdir" -type f -mtime +30 | xargs --no-run-if-empty rm -v
