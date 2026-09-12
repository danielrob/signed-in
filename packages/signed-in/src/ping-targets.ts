interface PingTargetService {
  accounts: Array<{ account: string; default: boolean }>;
  id: string;
  projectAccount?: string;
}

export interface ConnectionPingTarget {
  account: string;
  service: string;
}

// Keeps the normal one-per-service probe distinct from the explicit audit of every saved alias.
export function selectConnectionPingTargets(
  services: readonly PingTargetService[],
  everyConnection: boolean,
): ConnectionPingTarget[] {
  return services.flatMap((service) => {
    if (everyConnection) {
      return service.accounts.map((account) => ({ account: account.account, service: service.id }));
    }
    const selected = service.projectAccount
      ? service.accounts.find((account) => account.account === service.projectAccount)
      : service.accounts.find((account) => account.default) ?? service.accounts[0];
    return selected ? [{ account: selected.account, service: service.id }] : [];
  });
}
