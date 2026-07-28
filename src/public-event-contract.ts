import snapshot from './public-contracts/event-occurrence-v1.json' with { type: 'json' };

type JsonSchemaNode = {
  readonly type?: string;
  readonly const?: unknown;
  readonly pattern?: string;
  readonly format?: string;
  readonly minLength?: number;
  readonly maxLength?: number;
  readonly minimum?: number;
  readonly maximum?: number;
  readonly minItems?: number;
  readonly maxItems?: number;
  readonly uniqueItems?: boolean;
  readonly required?: readonly string[];
  readonly additionalProperties?: boolean;
  readonly properties?: Readonly<Record<string, JsonSchemaNode>>;
  readonly items?: JsonSchemaNode;
};

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const isRfc3339DateTime = (value: string): boolean =>
  /^(?:(?:\d\d[2468][048]|\d\d[13579][26]|\d\d0[48]|[02468][048]00|[13579][26]00)-02-29|\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\d|30)|(?:02)-(?:0[1-9]|1\d|2[0-8])))T(?:(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d))$/u.test(
    value,
  );

const validateNode = (schema: JsonSchemaNode, value: unknown, path: string): void => {
  if ('const' in schema && value !== schema.const) {
    throw new Error(`${path} must equal ${JSON.stringify(schema.const)}`);
  }
  if (schema.type === 'string') {
    if (typeof value !== 'string') throw new Error(`${path} must be a string`);
    if (schema.minLength !== undefined && [...value].length < schema.minLength) {
      throw new Error(`${path} is shorter than the public minimum`);
    }
    if (schema.maxLength !== undefined && [...value].length > schema.maxLength) {
      throw new Error(`${path} is longer than the public maximum`);
    }
    if (schema.pattern && !new RegExp(schema.pattern, 'u').test(value)) {
      throw new Error(`${path} does not match the public contract`);
    }
    if (schema.format === 'date-time' && !isRfc3339DateTime(value)) {
      throw new Error(`${path} must be an RFC 3339 date-time`);
    }
    return;
  }
  if (schema.type === 'number' || schema.type === 'integer') {
    if (
      typeof value !== 'number' ||
      !Number.isFinite(value) ||
      (schema.type === 'integer' && !Number.isInteger(value))
    ) {
      throw new Error(`${path} must be ${schema.type}`);
    }
    if (schema.minimum !== undefined && value < schema.minimum) {
      throw new Error(`${path} is below the public minimum`);
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      throw new Error(`${path} is above the public maximum`);
    }
    return;
  }
  if (schema.type === 'array') {
    if (!Array.isArray(value)) throw new Error(`${path} must be an array`);
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      throw new Error(`${path} has too few items`);
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      throw new Error(`${path} has too many items`);
    }
    if (schema.uniqueItems && new Set(value.map((item) => JSON.stringify(item))).size !== value.length) {
      throw new Error(`${path} items must be unique`);
    }
    if (!schema.items) throw new Error(`${path} public array contract has no item schema`);
    value.forEach((item, index) => validateNode(schema.items as JsonSchemaNode, item, `${path}[${index}]`));
    return;
  }
  if (schema.type === 'object') {
    if (!isPlainRecord(value)) throw new Error(`${path} must be a plain object`);
    const properties = schema.properties ?? {};
    for (const required of schema.required ?? []) {
      if (!(required in value)) throw new Error(`${path} is missing property ${JSON.stringify(required)}`);
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!(key in properties)) throw new Error(`${path} contains unknown property ${JSON.stringify(key)}`);
      }
    }
    for (const [key, childSchema] of Object.entries(properties)) {
      if (key in value) validateNode(childSchema, value[key], `${path}.${key}`);
    }
    return;
  }
  throw new Error(`${path} uses an unsupported public contract node`);
};

const variants = snapshot.variants as unknown as readonly JsonSchemaNode[];
const variantByEventType = new Map(
  variants.map((variant) => {
    const eventType = variant.properties?.eventType?.const;
    if (typeof eventType !== 'string') throw new Error('public contract variant is missing eventType');
    return [eventType, variant] as const;
  }),
);

export const PUBLIC_EVENT_CONTRACT_SOURCE_ID = snapshot.source.id;
export const PUBLIC_EVENT_CONTRACT_SOURCE_SHA256 = snapshot.source.sha256;
export const PUBLIC_EVENT_CONTRACT_VARIANTS_SHA256 = snapshot.selectedVariantsSha256;
export const PUBLIC_EVENT_CONTRACT_EVENT_TYPES = Object.freeze([...snapshot.selectedEventTypes]);

export const parsePublicEventOccurrence = <T>(input: unknown): T => {
  if (!isPlainRecord(input) || typeof input.eventType !== 'string') {
    throw new Error('event occurrence must be a plain object with eventType');
  }
  const variant = variantByEventType.get(input.eventType);
  if (!variant) throw new Error(`eventType ${JSON.stringify(input.eventType)} is not in the vendored public contract`);
  validateNode(variant, input, 'event occurrence');
  return input as T;
};
