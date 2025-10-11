
declare module '../utils/reportHelpers' {
  export function mapReasonToEnum(r: string | null | undefined): string;

  export type CreateReportParams = {
    prisma: any;
    reporterId: string;
    postId?: string | null;
    commentId?: string | null;
    reason: string;
    description?: string | null;
  };

  export function createReport(params: CreateReportParams): Promise<any>;
}

export {};
