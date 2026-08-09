import catalogData from './catalog-data.json' with { type: 'json' };

import { validateServiceCatalog } from './config.js';
import type { ServiceConfig } from './types.js';

const catalog = validateServiceCatalog(catalogData, 'built-in signed-in catalog');

export const builtInServices: Readonly<Record<string, ServiceConfig>> = Object.freeze(catalog.services);

// Returns one immutable packaged service definition with a stable error for typos and stale project bindings.
export function requireCatalogService(serviceId: string): ServiceConfig {
  const service = builtInServices[serviceId];
  if (!service) throw new Error(`Unknown service '${serviceId}'`);
  return service;
}
