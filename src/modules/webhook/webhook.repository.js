import { and, desc, eq, sql } from "drizzle-orm";
import db from "../../db/client/db.js";
import { webhookDeliveries } from "../../db/schemas/index.js";

export const createWebhookDelivery = async (payload, tx = db) => {
  const [created] = await tx
    .insert(webhookDeliveries)
    .values(payload)
    .returning();

  return created;
};

export const listWebhookDeliveriesByClient = async (
  orgId,
  clientId,
  { limit = 50, offset = 0, status, source, event } = {},
  tx = db,
) => {
  const clauses = [
    eq(webhookDeliveries.orgId, orgId),
    eq(webhookDeliveries.clientId, clientId),
  ];

  if (status) {
    clauses.push(eq(webhookDeliveries.status, status));
  }

  if (source) {
    clauses.push(eq(webhookDeliveries.source, source));
  }

  if (event) {
    clauses.push(eq(webhookDeliveries.event, event));
  }

  return tx
    .select()
    .from(webhookDeliveries)
    .where(and(...clauses))
    .orderBy(desc(webhookDeliveries.createdAt))
    .limit(limit)
    .offset(offset);
};

export const countWebhookDeliveriesByClient = async (
  orgId,
  clientId,
  { status, source, event } = {},
  tx = db,
) => {
  const clauses = [
    eq(webhookDeliveries.orgId, orgId),
    eq(webhookDeliveries.clientId, clientId),
  ];

  if (status) {
    clauses.push(eq(webhookDeliveries.status, status));
  }

  if (source) {
    clauses.push(eq(webhookDeliveries.source, source));
  }

  if (event) {
    clauses.push(eq(webhookDeliveries.event, event));
  }

  const [result] = await tx
    .select({ count: sql`count(*)::int` })
    .from(webhookDeliveries)
    .where(and(...clauses));

  return Number(result?.count || 0);
};

export const findWebhookDeliveryById = async (
  orgId,
  clientId,
  deliveryId,
  tx = db,
) => {
  const [delivery] = await tx
    .select()
    .from(webhookDeliveries)
    .where(
      and(
        eq(webhookDeliveries.id, deliveryId),
        eq(webhookDeliveries.orgId, orgId),
        eq(webhookDeliveries.clientId, clientId),
      ),
    )
    .limit(1);

  return delivery || null;
};

export const getWebhookDeliveryStatusSummary = async (
  orgId,
  clientId,
  tx = db,
) => {
  const [summary] = await tx
    .select({
      totalCount: sql`count(*)::int`,
      successCount: sql`sum(case when ${webhookDeliveries.status} = 'success' then 1 else 0 end)::int`,
      failedCount: sql`sum(case when ${webhookDeliveries.status} = 'failed' then 1 else 0 end)::int`,
      lastDeliveredAt: sql`max(${webhookDeliveries.deliveredAt})`,
      lastSuccessAt: sql`max(case when ${webhookDeliveries.status} = 'success' then ${webhookDeliveries.deliveredAt} else null end)`,
      lastFailureAt: sql`max(case when ${webhookDeliveries.status} = 'failed' then ${webhookDeliveries.deliveredAt} else null end)`,
    })
    .from(webhookDeliveries)
    .where(
      and(
        eq(webhookDeliveries.orgId, orgId),
        eq(webhookDeliveries.clientId, clientId),
      ),
    );

  const [lastFailure] = await tx
    .select({
      id: webhookDeliveries.id,
      errorMessage: webhookDeliveries.errorMessage,
      httpStatus: webhookDeliveries.httpStatus,
      deliveredAt: webhookDeliveries.deliveredAt,
      event: webhookDeliveries.event,
    })
    .from(webhookDeliveries)
    .where(
      and(
        eq(webhookDeliveries.orgId, orgId),
        eq(webhookDeliveries.clientId, clientId),
        eq(webhookDeliveries.status, "failed"),
      ),
    )
    .orderBy(desc(webhookDeliveries.deliveredAt))
    .limit(1);

  return {
    totalCount: Number(summary?.totalCount || 0),
    successCount: Number(summary?.successCount || 0),
    failedCount: Number(summary?.failedCount || 0),
    lastDeliveredAt: summary?.lastDeliveredAt || null,
    lastSuccessAt: summary?.lastSuccessAt || null,
    lastFailureAt: summary?.lastFailureAt || null,
    lastFailure: lastFailure || null,
  };
};
