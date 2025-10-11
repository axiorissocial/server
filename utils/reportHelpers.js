export const mapReasonToEnum = (r) => {
  if (!r || typeof r !== 'string') return 'OTHER';
  const normalized = r.trim().toLowerCase();
  switch (normalized) {
    case 'spam':
      return 'SPAM';
    case 'harassment':
    case 'abuse':
      return 'HARASSMENT';
    case 'sexual':
    case 'inappropriate':
      return 'INAPPROPRIATE_CONTENT';
    case 'copyright':
    case 'copyright_violation':
      return 'COPYRIGHT_VIOLATION';
    case 'misinformation':
      return 'MISINFORMATION';
    case 'hate':
    case 'hate_speech':
      return 'HATE_SPEECH';
    case 'violence':
      return 'VIOLENCE';
    case 'other':
      return 'OTHER';
    default:
      if (typeof r === 'string' && ['SPAM','HARASSMENT','INAPPROPRIATE_CONTENT','COPYRIGHT_VIOLATION','MISINFORMATION','HATE_SPEECH','VIOLENCE','OTHER'].includes(r.toUpperCase())) {
        return r.toUpperCase();
      }
      return 'OTHER';
  }
};

export const createReport = async ({ prisma, reporterId, postId, commentId, reason, description }) => {
  if (!reason) throw new Error('Reason is required');
  if (!postId && !commentId) throw new Error('Must specify either postId or commentId');
  if (postId && commentId) throw new Error('Cannot specify both postId and commentId');

  if (postId) {
    const post = await prisma.post.findUnique({ where: { id: postId } });
    if (!post) throw new Error('Post not found');
  }

  if (commentId) {
    const comment = await prisma.comment.findUnique({ where: { id: commentId } });
    if (!comment) throw new Error('Comment not found');
  }

  const existing = await prisma.report.findFirst({ where: { reporterId, ...(postId ? { postId } : { commentId }) } });
  if (existing) throw new Error('You have already reported this item');

  const reasonEnum = mapReasonToEnum(reason);
  const createData = { reporterId, postId, commentId, reason: reasonEnum, description: description ?? null };
  const report = await prisma.report.create({ data: createData });
  return report;
};
