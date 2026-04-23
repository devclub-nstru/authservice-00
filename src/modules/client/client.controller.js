import {
  configureOrganizationClientWebhookSchema,
  createOrganizationClientSchema,
  createOrganizationClientProviderSchema,
  listOrganizationClientWebhookDeliveriesQuerySchema,
  listOrganizationClientUsersQuerySchema,
  organizationClientParamSchema,
  organizationClientProviderParamSchema,
  organizationClientWebhookDeliveryParamSchema,
  replayOrganizationClientWebhookDeliverySchema,
  rotateOrganizationClientSecretSchema,
  rotateOrganizationClientWebhookSecretSchema,
  testOrganizationClientWebhookSchema,
  updateOrganizationClientProviderSchema,
  updateOrganizationClientSchema,
  verifyOrganizationClientWebhookSchema,
} from "../../validations/client/client.validators.js";
import {
  addOrganizationClientProviderForUser,
  configureOrganizationClientWebhookForUser,
  createOrganizationClientForUser,
  deleteOrganizationClientForUser,
  deleteOrganizationClientProviderForUser,
  disableOrganizationClientWebhookForUser,
  getOrganizationClientForUser,
  listOrganizationClientUsersForUser,
  listOrganizationClientsForUser,
  rotateOrganizationClientSecretForUser,
  rotateOrganizationClientWebhookSecretForUser,
  updateOrganizationClientForUser,
  updateOrganizationClientProviderForUser,
} from "./client.service.js";
import {
  getWebhookDeliveryForUser,
  getWebhookStatusForUser,
  listWebhookDeliveriesForUser,
  replayWebhookDeliveryForUser,
  testWebhookForUser,
  verifyWebhookOwnershipForUser,
} from "../webhook/webhook-admin.service.js";
import {
  AUDIT_CATEGORY,
  AUDIT_EVENTS,
  AUDIT_STATUS,
} from "../audit/audit.events.js";
import {
  buildAuditContextFromRequest,
  emitAuditEvent,
} from "../audit/audit.service.js";
import { AUDIT_MESSAGES } from "../audit/audit.messages.js";
import { CLIENT_MESSAGES } from "./client.constants.js";

export const createOrganizationClientHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId } = organizationClientParamSchema
    .omit({ clientId: true })
    .parse(req.params);
  const payload = createOrganizationClientSchema.parse(req.body);

  const result = await createOrganizationClientForUser(
    orgId,
    req.auth.sub,
    payload,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_CREATED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_CREATED,
    metadata: {
      clientId: result.client.id,
      name: result.client.name,
    },
  });

  res.status(201).json({
    client: result.client,
    clientSecret: result.clientSecret,
  });
};

export const listOrganizationClientsHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId } = organizationClientParamSchema
    .omit({ clientId: true })
    .parse(req.params);

  const clients = await listOrganizationClientsForUser(orgId, req.auth.sub);

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENTS_LISTED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENTS_LISTED,
    metadata: {
      count: clients.length,
    },
  });

  res.status(200).json({ clients });
};

export const getOrganizationClientHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId } = organizationClientParamSchema.parse(req.params);

  const client = await getOrganizationClientForUser(
    orgId,
    clientId,
    req.auth.sub,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_VIEWED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_VIEWED,
    metadata: {
      clientId,
    },
  });

  res.status(200).json({ client });
};

export const updateOrganizationClientHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId } = organizationClientParamSchema.parse(req.params);
  const payload = updateOrganizationClientSchema.parse(req.body);

  const client = await updateOrganizationClientForUser(
    orgId,
    clientId,
    req.auth.sub,
    payload,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_UPDATED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_UPDATED,
    metadata: {
      clientId,
      updatedFields: Object.keys(payload),
    },
  });

  res.status(200).json({ client });
};

export const deleteOrganizationClientHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId } = organizationClientParamSchema.parse(req.params);

  const message = await deleteOrganizationClientForUser(
    orgId,
    clientId,
    req.auth.sub,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_DELETED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_DELETED,
    metadata: {
      clientId,
    },
  });

  res.status(200).json({ message });
};

export const addOrganizationClientProviderHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId } = organizationClientParamSchema.parse(req.params);
  const payload = createOrganizationClientProviderSchema.parse(req.body);

  const provider = await addOrganizationClientProviderForUser(
    orgId,
    clientId,
    req.auth.sub,
    payload,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_PROVIDER_ADDED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_PROVIDER_ADDED,
    metadata: {
      clientId,
      provider: provider.provider,
    },
  });

  res
    .status(201)
    .json({ message: CLIENT_MESSAGES.PROVIDER_CONFIGURED, provider });
};

export const updateOrganizationClientProviderHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId, provider } =
    organizationClientProviderParamSchema.parse(req.params);
  const payload = updateOrganizationClientProviderSchema.parse(req.body);

  const updatedProvider = await updateOrganizationClientProviderForUser(
    orgId,
    clientId,
    provider,
    req.auth.sub,
    payload,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_PROVIDER_UPDATED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_PROVIDER_UPDATED,
    metadata: {
      clientId,
      provider,
      rotatedSecret: Boolean(payload.providerClientSecret),
    },
  });

  res.status(200).json({
    message: CLIENT_MESSAGES.PROVIDER_UPDATED,
    provider: updatedProvider,
  });
};

export const deleteOrganizationClientProviderHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId, provider } =
    organizationClientProviderParamSchema.parse(req.params);

  const message = await deleteOrganizationClientProviderForUser(
    orgId,
    clientId,
    provider,
    req.auth.sub,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_PROVIDER_REMOVED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_PROVIDER_REMOVED,
    metadata: {
      clientId,
      provider,
    },
  });

  res.status(200).json({ message });
};

export const configureOrganizationClientWebhookHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId } = organizationClientParamSchema.parse(req.params);
  const payload = configureOrganizationClientWebhookSchema.parse(req.body);

  const webhook = await configureOrganizationClientWebhookForUser(
    orgId,
    clientId,
    req.auth.sub,
    payload,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_WEBHOOK_CONFIGURED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_WEBHOOK_CONFIGURED,
    metadata: {
      clientId,
      webhookUrl: webhook.webhookUrl,
    },
  });

  res
    .status(200)
    .json({ message: CLIENT_MESSAGES.WEBHOOK_CONFIGURED, webhook });
};

export const disableOrganizationClientWebhookHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId } = organizationClientParamSchema.parse(req.params);

  const message = await disableOrganizationClientWebhookForUser(
    orgId,
    clientId,
    req.auth.sub,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_WEBHOOK_DISABLED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_WEBHOOK_DISABLED,
    metadata: {
      clientId,
    },
  });

  res.status(200).json({ message });
};

export const rotateOrganizationClientWebhookSecretHandler = async (
  req,
  res,
) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId } = organizationClientParamSchema.parse(req.params);

  rotateOrganizationClientWebhookSecretSchema.parse(req.body || {});

  const webhook = await rotateOrganizationClientWebhookSecretForUser(
    orgId,
    clientId,
    req.auth.sub,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_WEBHOOK_CONFIGURED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_WEBHOOK_CONFIGURED,
    metadata: {
      clientId,
      webhookUrl: webhook.webhookUrl,
      rotatedWebhookSecret: true,
    },
  });

  res.status(200).json({
    message: CLIENT_MESSAGES.WEBHOOK_SECRET_ROTATED,
    webhook,
  });
};

export const listOrganizationClientWebhookDeliveriesHandler = async (
  req,
  res,
) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId } = organizationClientParamSchema.parse(req.params);
  const query = listOrganizationClientWebhookDeliveriesQuerySchema.parse(
    req.query,
  );

  const result = await listWebhookDeliveriesForUser({
    orgId,
    clientId,
    actorUserId: req.auth.sub,
    query,
  });

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_WEBHOOK_DELIVERIES_VIEWED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_WEBHOOK_DELIVERIES_VIEWED,
    metadata: {
      clientId,
      count: result.deliveries.length,
      limit: query.limit,
      offset: query.offset,
      status: query.status || null,
      source: query.source || null,
      eventName: query.event || null,
    },
  });

  res.status(200).json(result);
};

export const getOrganizationClientWebhookDeliveryHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId, deliveryId } =
    organizationClientWebhookDeliveryParamSchema.parse(req.params);

  const delivery = await getWebhookDeliveryForUser({
    orgId,
    clientId,
    deliveryId,
    actorUserId: req.auth.sub,
  });

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_WEBHOOK_DELIVERIES_VIEWED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_WEBHOOK_DELIVERIES_VIEWED,
    metadata: {
      clientId,
      deliveryId,
    },
  });

  res.status(200).json({ delivery });
};

export const replayOrganizationClientWebhookDeliveryHandler = async (
  req,
  res,
) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId, deliveryId } =
    organizationClientWebhookDeliveryParamSchema.parse(req.params);

  replayOrganizationClientWebhookDeliverySchema.parse(req.body || {});

  const replayResult = await replayWebhookDeliveryForUser({
    orgId,
    clientId,
    deliveryId,
    actorUserId: req.auth.sub,
  });

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_WEBHOOK_DELIVERY_REPLAYED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_WEBHOOK_DELIVERY_REPLAYED,
    metadata: {
      clientId,
      deliveryId,
      idempotencyKey: replayResult.idempotencyKey,
    },
  });

  res.status(202).json(replayResult);
};

export const getOrganizationClientWebhookStatusHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId } = organizationClientParamSchema.parse(req.params);

  const status = await getWebhookStatusForUser({
    orgId,
    clientId,
    actorUserId: req.auth.sub,
  });

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_WEBHOOK_DELIVERIES_VIEWED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_WEBHOOK_DELIVERIES_VIEWED,
    metadata: {
      clientId,
      statusView: true,
    },
  });

  res.status(200).json({ status });
};

export const testOrganizationClientWebhookHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId } = organizationClientParamSchema.parse(req.params);
  const payload = testOrganizationClientWebhookSchema.parse(req.body || {});

  const result = await testWebhookForUser({
    orgId,
    clientId,
    actorUserId: req.auth.sub,
    payload: payload.payload,
  });

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_WEBHOOK_TEST_TRIGGERED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: result.success ? AUDIT_STATUS.SUCCESS : AUDIT_STATUS.FAILURE,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_WEBHOOK_TEST_TRIGGERED,
    metadata: {
      clientId,
      success: result.success,
      httpStatus: result.httpStatus,
      idempotencyKey: result.idempotencyKey,
    },
  });

  res.status(200).json({
    message: CLIENT_MESSAGES.WEBHOOK_TEST_SENT,
    test: result,
  });
};

export const verifyOrganizationClientWebhookHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId } = organizationClientParamSchema.parse(req.params);

  verifyOrganizationClientWebhookSchema.parse(req.body || {});

  const verification = await verifyWebhookOwnershipForUser({
    orgId,
    clientId,
    actorUserId: req.auth.sub,
  });

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_WEBHOOK_VERIFIED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_WEBHOOK_VERIFIED,
    metadata: {
      clientId,
      challenge: verification.challenge,
      verifiedAt: verification.verifiedAt,
    },
  });

  res.status(200).json({
    message: CLIENT_MESSAGES.WEBHOOK_VERIFIED,
    verification,
  });
};

export const rotateOrganizationClientSecretHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId } = organizationClientParamSchema.parse(req.params);

  rotateOrganizationClientSecretSchema.parse(req.body || {});

  const result = await rotateOrganizationClientSecretForUser(
    orgId,
    clientId,
    req.auth.sub,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENT_UPDATED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENT_UPDATED,
    metadata: {
      clientId,
      rotatedClientSecret: true,
    },
  });

  res.status(200).json({
    message: CLIENT_MESSAGES.CLIENT_SECRET_ROTATED,
    client: result.client,
    clientSecret: result.clientSecret,
  });
};

export const listOrganizationClientUsersHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, clientId } = organizationClientParamSchema.parse(req.params);
  const query = listOrganizationClientUsersQuerySchema.parse(req.query);

  const users = await listOrganizationClientUsersForUser(
    orgId,
    clientId,
    req.auth.sub,
    query,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CLIENTS_LISTED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_CLIENTS_LISTED,
    metadata: {
      clientId,
      count: users.length,
      limit: query.limit,
      offset: query.offset,
    },
  });

  res.status(200).json({
    users,
    pagination: {
      limit: query.limit,
      offset: query.offset,
      count: users.length,
    },
  });
};
