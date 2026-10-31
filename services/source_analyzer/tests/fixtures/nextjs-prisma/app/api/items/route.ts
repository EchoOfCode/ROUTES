import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
export async function GET() {
  return Response.json(await prisma.item.findMany());
}
