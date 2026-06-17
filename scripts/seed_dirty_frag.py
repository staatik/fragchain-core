"""Seed CVE-2026-43284 ("Dirty Frag") for local development.

Run inside the API container with the DB up:

    python -m scripts.seed_dirty_frag

Idempotent — re-runs upsert the row rather than creating duplicates. The CVE
lands in ``processing_status='pending'`` with ``import_mode='live'`` so the
next ``enrich_cve`` task picks it up.

Also seeds three source documents on the CVE so M8's embedding pipeline has
something real to chunk + embed end-to-end. The documents carry their
content in ``document_metadata.content`` (inline) so a fresh deployment
doesn't need a connector to produce useful RAG output.
"""
from __future__ import annotations

import asyncio
from datetime import date, datetime, timezone

import structlog

from fragchain.connectors import CVERecord
from fragchain.db.session import dispose_engine, get_sessionmaker
from fragchain.ingest.service import persist_documents, upsert_cve_from_record
from fragchain.security.tlp import TLP

logger = structlog.get_logger(__name__)


DIRTY_FRAG_DOCS = [
    {
        "url": "https://www.cve.org/CVERecord?id=CVE-2026-43284",
        "source_type": "advisory",
        "connector": "seed:dirty-frag",
        "quality_score": 0.95,
        "tlp": "tlp:clear",
        "content": (
            "CVE-2026-43284 — Dirty Frag. A use-after-free vulnerability in the "
            "Linux kernel page allocator allows an unprivileged local user to "
            "trigger a memory-fragmentation race during a partial write across "
            "two adjacent pages. The race window opens when copy_page_range "
            "splits a transparent huge page (THP) under memory pressure: the "
            "fragmenting thread retains a stale PMD reference while the writing "
            "thread re-issues the partial write against an alias of the freed "
            "page. The result is a write-anywhere primitive constrained by the "
            "alias coverage. Exploitation requires CAP_SYS_NICE-like control over "
            "task scheduling and a controllable page allocation pattern. "
            "Demonstrated against kernels 6.6.0 through 6.8.0; older kernels are "
            "not affected because the THP split path differs."
        ),
    },
    {
        "url": "https://github.com/fragchain/dirty-frag-poc",
        "source_type": "poc",
        "connector": "seed:dirty-frag",
        "quality_score": 0.80,
        "tlp": "tlp:clear",
        "content": (
            "Dirty Frag PoC notes. The proof-of-concept stages a victim THP "
            "via /proc/self/mem followed by a controlled madvise(MADV_DONTNEED) "
            "to free half the huge page. Two threads race: thread A issues "
            "userfaultfd-mediated partial writes; thread B issues a parallel "
            "fragmenting allocation that re-acquires the freed half. With "
            "MADV_NOHUGEPAGE on the parent process and SCHED_FIFO priority on "
            "thread A, the race window is reliably observable within "
            "~20 attempts on a 6-core host. The PoC then escalates to root via "
            "modprobe_path overwrite, the same vector used in DirtyCred. "
            "Suggested detection: anomalous madvise() call patterns from "
            "non-privileged userspace, especially MADV_DONTNEED followed within "
            "1ms by writes to /proc/self/mem; alerting on modprobe_path writes "
            "from non-root tasks is the high-confidence signal."
        ),
    },
    {
        "url": "https://lwn.net/Articles/dirty-frag/",
        "source_type": "writeup",
        "connector": "seed:dirty-frag",
        "quality_score": 0.85,
        "tlp": "tlp:clear",
        "content": (
            "LWN: Dirty Frag and the cost of transparent huge pages. The kernel "
            "community is converging on a multi-layer fix. The first patch "
            "tightens the THP split path under copy_page_range — splits now "
            "take an exclusive PMD lock for the duration of the migration, "
            "closing the alias window. The second patch hardens the modprobe "
            "trampoline: kernel.modprobe sysctl writes are now restricted to "
            "CAP_SYS_MODULE-bearing tasks, which kills the most popular "
            "exploitation path. Discussion in the thread suggested making "
            "MADV_NOHUGEPAGE refuse to operate on tasks running at SCHED_FIFO, "
            "but the maintainers rejected that as too narrow. Sysadmins are "
            "advised to ensure auditd captures execve() of unexpected binaries "
            "spawned by modprobe-shaped processes — Sigma rule "
            "'Linux Suspicious Modprobe Child' (SigmaHQ) catches this when "
            "modprobe_path has been redirected to /tmp."
        ),
    },
]


DIRTY_FRAG = CVERecord(
    cve_id="CVE-2026-43284",
    published=datetime(2026, 3, 12, 10, 0, 0, tzinfo=timezone.utc),
    modified=datetime(2026, 4, 18, 10, 0, 0, tzinfo=timezone.utc),
    description=(
        "Memory-fragmentation race in the FragChain reference kernel that allows "
        "an unprivileged local user to escalate to root by colliding two adjacent "
        "page allocations during a partial write. Variant of the classic 'Dirty "
        "Pipe' bug, repurposed into the FragChain test corpus."
    ),
    cvss_v3=8.4,
    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    affected_products=[
        "linux:kernel:6.6.0",
        "linux:kernel:6.7.0",
        "linux:kernel:6.8.0",
    ],
    references=[
        "https://www.cve.org/CVERecord?id=CVE-2026-43284",
        "https://github.com/fragchain/dirty-frag-poc",
        "https://lwn.net/Articles/dirty-frag/",
    ],
    raw={
        "cisa_kev": True,
        "cisa_kev_date": "2026-04-22",
        "source": "seed:dirty-frag",
    },
    source="seed:dirty-frag",
    tlp=TLP.CLEAR,
)


async def _run() -> None:
    sm = get_sessionmaker()
    async with sm() as session:
        cve, created = await upsert_cve_from_record(
            session,
            DIRTY_FRAG,
            import_mode="live",
            initial_status="pending",
        )
        # Ensure KEV flags survive even after the upsert short-circuited the
        # row from `failed`.
        cve.cisa_kev = True
        cve.cisa_kev_date = date(2026, 4, 22)
        # Attach a handful of source documents so M8's embedding pipeline
        # has real RAG input. persist_documents dedups by content hash so
        # re-runs don't pile up duplicates.
        inserted = await persist_documents(session, cve, DIRTY_FRAG_DOCS)
        await session.commit()
        logger.info(
            "seed.dirty_frag",
            cve_id=cve.cve_id,
            id=str(cve.id),
            status=cve.processing_status,
            created=created,
            documents_inserted=inserted,
        )
        print(
            f"{'CREATED' if created else 'UPDATED'} {cve.cve_id} "
            f"(id={cve.id}, status={cve.processing_status}, "
            f"new_documents={inserted})"
        )


async def _run_and_dispose() -> None:
    try:
        await _run()
    finally:
        await dispose_engine()


def main() -> None:
    # Single event loop for the whole lifecycle so asyncpg's connection-close
    # coroutines see the same loop they were created on (Phase 4 audit C0c).
    asyncio.run(_run_and_dispose())


if __name__ == "__main__":
    main()
