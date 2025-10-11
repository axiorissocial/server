// Loose Prisma shim declarations to speed up initial TypeScript setup.
// Matches any import path that contains prisma/generated and treats
// PrismaClient as having arbitrary properties (index signature).

declare module '*prisma/generated*' {
  export class PrismaClient {
    constructor(...args: any[]);
    [key: string]: any;
  }

  export const NotificationType: any;
}

export {};
