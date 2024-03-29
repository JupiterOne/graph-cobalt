import {
  createDirectRelationship,
  createIntegrationEntity,
  IntegrationStep,
  IntegrationStepExecutionContext,
  RelationshipClass,
} from '@jupiterone/integration-sdk-core';

import { IntegrationConfig } from '../types';
import { createAPIClient } from '../client';

export const DATA_ACCOUNT_ENTITY = 'DATA_ACCOUNT_ENTITY';
export const VENDOR_ENTITY_KEY = 'cobalt-vendor';
export const SERVICE_ENTITY_KEY = 'cobalt-service';

export async function fetchAccountDetails({
  jobState,
  instance,
}: IntegrationStepExecutionContext<IntegrationConfig>) {
  const apiClient = createAPIClient(instance.config);

  await apiClient.getAccount(async (org) => {
    org.resource.token = '[REDACTED]';
    const accountEntity = await jobState.addEntity(
      createIntegrationEntity({
        entityData: {
          source: org,
          assign: {
            _key: `cobalt-account:${instance.id}`,
            _type: 'cobalt_account',
            _class: 'Account',
            name: org.resource.name,
            displayName: org.resource.name,
            id: org.resource.id,
            webLink: org.links?.ui?.url,
          },
        },
      }),
    );
    await jobState.setData(DATA_ACCOUNT_ENTITY, accountEntity);

    const vendorEntity = await jobState.addEntity(
      createIntegrationEntity({
        entityData: {
          source: {},
          assign: {
            _key: VENDOR_ENTITY_KEY,
            _type: 'cobalt_vendor',
            _class: 'Vendor',
            name: 'Cobalt',
            displayName: 'Cobalt',
            category: 'security',
          },
        },
      }),
    );

    const serviceEntity = await jobState.addEntity(
      createIntegrationEntity({
        entityData: {
          source: {},
          assign: {
            _key: SERVICE_ENTITY_KEY,
            _type: 'cobalt_service',
            _class: 'Service',
            name: 'Cobalt pentest service',
            displayName: 'Cobalt pentest service',
            category: ['security'],
            function: ['PenTest'],
          },
        },
      }),
    );

    await jobState.addRelationship(
      createDirectRelationship({
        _class: RelationshipClass.PROVIDES,
        from: vendorEntity,
        to: serviceEntity,
      }),
    );

    await jobState.addRelationship(
      createDirectRelationship({
        _class: RelationshipClass.HAS,
        from: accountEntity,
        to: serviceEntity,
      }),
    );
  });
}

export const accountSteps: IntegrationStep<IntegrationConfig>[] = [
  {
    id: 'fetch-account',
    name: 'Fetch Account Details',
    entities: [
      {
        resourceName: 'Cobalt Account',
        _type: 'cobalt_account',
        _class: 'Account',
      },
      {
        resourceName: 'Cobalt',
        _type: 'cobalt_vendor',
        _class: 'Vendor',
      },
      {
        resourceName: 'Cobalt pentest service',
        _type: 'cobalt_service',
        _class: 'Service',
      },
    ],
    relationships: [
      {
        _type: 'cobalt_account_has_service',
        _class: RelationshipClass.HAS,
        sourceType: 'cobalt_account',
        targetType: 'cobalt_service',
      },
      {
        _type: 'cobalt_vendor_provides_service',
        _class: RelationshipClass.PROVIDES,
        sourceType: 'cobalt_vendor',
        targetType: 'cobalt_service',
      },
    ],
    dependsOn: [],
    executionHandler: fetchAccountDetails,
  },
];
