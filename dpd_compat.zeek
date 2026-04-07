##! Recreate dpd.log for Zeek 8.x.
##!
##! In Zeek 7.2 the built-in DPD log was removed (PR #4200).  Protocol
##! analyzer violations now fire the ``analyzer_failed`` event instead.
##! This script hooks that event and writes a ``dpd.log`` with the same
##! columns that the old built-in log produced.
##!
##! Tested against Zeek 8.0.5.  The ``AnalyzerViolationInfo`` record used
##! here has the following optional fields:
##!   reason : string         -- human-readable failure message
##!   c      : connection     -- the triggering connection (&optional)
##!   f      : fa_file        -- the triggering file   (&optional)
##!   aid    : count          -- analyzer instance id   (&optional)
##!   data   : string         -- offending payload      (&optional)
##!
##! Only events that have an associated connection (``info?$c``) are logged;
##! file-level violations are skipped because they lack src/dst port info.

module DPDCompat;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts             : time              &log;
        uid            : string            &log;
        id             : conn_id           &log;
        proto          : transport_proto   &log;
        analyzer       : string            &log;
        failure_reason : string            &log;
    };
}

event zeek_init() &priority=5
    {
    Log::create_stream(DPDCompat::LOG, [$columns=Info, $path="dpd"]);
    }

event analyzer_failed(ts: time, atype: AllAnalyzers::Tag,
                      info: AnalyzerViolationInfo)
    {
    # Skip violations that have no associated connection (e.g. file analyzers)
    if ( ! info?$c )
        return;

    local c = info$c;

    local rec: DPDCompat::Info = [
        $ts             = ts,
        $uid            = c$uid,
        $id             = c$id,
        $proto          = get_port_transport_proto(c$id$orig_p),
        $analyzer       = fmt("%s", atype),
        $failure_reason = info$reason
    ];

    Log::write(DPDCompat::LOG, rec);
    }
