"use client";

import { Activity } from "lucide-react";

import { AssessmentsTable } from "@/components/app/assessments-table";
import { EmptyState, Loading, Notice, PageBody, PageHeader } from "@/components/app/layout-parts";
import { useApi } from "@/hooks/use-api";
import { ACTIVE_STATUSES, type Assessment } from "@/lib/api";

export default function AssessmentsPage() {
  const { data, error, loading } = useApi<Assessment[]>("/assessments", {
    poll: (list) => list.some((a) => ACTIVE_STATUSES.includes(a.status)),
    intervalMs: 3000,
  });
  return (
    <>
      <PageHeader title="Assessments" description="All retained assessments across your projects (up to five per project)." />
      <PageBody>
        {loading && !data && <Loading />}
        {error && <Notice tone="bad">{error.message}</Notice>}
        {data && data.length === 0 && (
          <EmptyState icon={Activity} title="No assessments yet">Assessments start automatically when you create a project.</EmptyState>
        )}
        {data && data.length > 0 && <AssessmentsTable assessments={data} showProject />}
      </PageBody>
    </>
  );
}
