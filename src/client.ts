import axios, { AxiosInstance } from 'axios';

import { IntegrationProviderAuthenticationError } from '@jupiterone/integration-sdk-core';

import { IntegrationConfig } from './types';

export type ResourceIteratee<T> = (each: T) => Promise<void> | void;

type CobaltOrg = {
  resource: {
    id: string;
    name: string;
    token?: string;
  };
};

type CobaltAsset = {
  resource: {
    id: string;
    title: string;
    description: string;
    asset_type: string;
    attachments?: object[]; // { token: string, download_url: string }, refers to documents about asset
  };
};

type CobaltPentest = {
  resource: {
    id: string;
    title: string;
    objectives: string;
    state: string; //enum 'new', 'in_review', 'live', 'paused', 'closed', 'cancelled', 'planned', 'remediation'
    tag: string;
    asset_id: string;
    platform_tags: string[];
    methodology: string;
    targets: string[];
    start_date: string;
    end_date: string;
  };
};

type CobaltFinding = {
  resource: {
    id: string;
    tag: string;
    title: string;
    description: string;
    type_category: string;
    labels: object[]; // { name: string }
    impact: number; //range 1 to 5
    likelihood: number; // range 1 to 5
    severity: string; //enum low,medium,high
    state: string; //enum 'created', 'pending_fix', 'ready_for_re_test', 'accepted_risk', 'fixed', 'carried_over'
    affected_targets: string[];
    proof_of_concept: string;
    suggested_fix: string;
    prerequisites?: string;
    pentest_id: string;
    asset_id?: string;
    log?: object[]; // { action: string, timestamp: string}, values for action per 'state' field above
  };
};

/**
 * An APIClient maintains authentication state and provides an interface to
 * third party data APIs.
 */
export class APIClient {
  orgToken: string;
  constructor(readonly config: IntegrationConfig) {}

  getClient(): AxiosInstance {
    const client = axios.create({
      headers: {
        get: {
          client: 'JupiterOne-Cobalt Integration client',
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.config.apiKeyAuth}`,
          'X-Org-Token': this.orgToken || '', //can't send undefined in HTTP
        },
      },
    });
    return client;
  }

  public async verifyAuthentication(): Promise<void> {
    // the most light-weight request possible to validate
    // authentication works with the provided credentials, throw an err if
    // authentication fails
    return await this.contactAPI('https://api.cobalt.io/orgs');
  }

  /**
   * Add account info.
   *
   * @param iteratee receives the raw account info to produce entities/relationships
   */
  public async addAccount(
    iteratee: ResourceIteratee<CobaltOrg>,
  ): Promise<void> {
    const orgs: CobaltOrg[] = await this.contactAPI(
      'https://api.cobalt.io/orgs',
    );
    await iteratee(orgs[0]);
  }

  /**
   * Iterates each finding resource in the provider.
   *
   * @param iteratee receives each resource to produce entities/relationships
   */
  public async iterateFindings(
    iteratee: ResourceIteratee<CobaltFinding>,
  ): Promise<void> {
    const findings: CobaltFinding[] = await this.contactAPI(
      'https://api.cobalt.io/findings',
    );

    for (const finding of findings) {
      await iteratee(finding);
    }
  }

  /**
   * Iterates each pentest (penetration test) resource in the provider.
   *
   * @param iteratee receives each resource to produce entities/relationships
   */
  public async iteratePentests(
    iteratee: ResourceIteratee<CobaltPentest>,
  ): Promise<void> {
    const pentests: CobaltPentest[] = await this.contactAPI(
      'https://api.cobalt.io/pentests',
    );

    for (const pentest of pentests) {
      await iteratee(pentest);
    }
  }

  /**
   * Iterates each pentest (penetration test) resource in the provider.
   *
   * @param iteratee receives each resource to produce entities/relationships
   */
  public async iterateAssets(
    iteratee: ResourceIteratee<CobaltAsset>,
  ): Promise<void> {
    const assets: CobaltAsset[] = await this.contactAPI(
      'https://api.cobalt.io/assets',
    );

    for (const asset of assets) {
      await iteratee(asset);
    }
  }

  public async contactAPI(url, params?) {
    let reply;
    let replyErrorDetected = false;
    if (!this.orgToken) {
      await this.updateOrgToken();
    }
    try {
      reply = await this.getClient().get(url, params);
    } catch (err) {
      replyErrorDetected = true;
    }
    if (replyErrorDetected || reply.status !== 200) {
      //maybe token expired
      try {
        await this.updateOrgToken();
        reply = await this.getClient().get(url, params);
      } catch (err) {
        //something is really failing
        throw new IntegrationProviderAuthenticationError({
          cause: err,
          endpoint: url,
          status: err.response.status,
          statusText: err.response,
        });
      }
    }
    if (reply.status !== 200) {
      //we're getting a reply, but it's not a useful one
      throw new IntegrationProviderAuthenticationError({
        endpoint: url,
        status: reply.status,
        statusText: `Received HTTP status ${reply.status} while fetching ${url}`,
      });
    }
    return reply.data.data;
  }

  //there are two reasons we might need an orgToken - either we never got it, or it expired
  public async updateOrgToken() {
    try {
      const tokenSearch = await this.getClient().get(
        'https://api.cobalt.io/orgs',
      );
      if (tokenSearch.status != 200) {
        throw new IntegrationProviderAuthenticationError({
          endpoint: 'https://api.cobalt.io/orgs',
          status: tokenSearch.status,
          statusText: `Received HTTP status ${tokenSearch.status} while trying to update token. Please check API_KEY_AUTH.`,
        });
      }
      this.orgToken = tokenSearch.data.data[0].resource.token;
    } catch (err) {
      throw new IntegrationProviderAuthenticationError({
        cause: err,
        endpoint: `https://api.cobalt.io/orgs`,
        status: err.response.status,
        statusText: err.response,
      });
    }
  }
}

export function createAPIClient(config: IntegrationConfig): APIClient {
  return new APIClient(config);
}
