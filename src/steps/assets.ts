import {
  createDirectRelationship,
  createIntegrationEntity,
  Entity,
  IntegrationStep,
  IntegrationStepExecutionContext,
  RelationshipClass,
} from '@jupiterone/integration-sdk-core';

import { createAPIClient } from '../client';
import { IntegrationConfig } from '../types';
import { DATA_ACCOUNT_ENTITY } from './account';

export async function fetchAssets({
  instance,
  jobState,
}: IntegrationStepExecutionContext<IntegrationConfig>) {
  const apiClient = createAPIClient(instance.config);
  const accountEntity = (await jobState.getData(DATA_ACCOUNT_ENTITY)) as Entity;
  await apiClient.iterateAssets(async (asset) => {
    delete asset.resource.attachments; //these have a uniquely generated AWS hash that triggers gitleaks
    const assetProps = asset.resource;
    const classesAssigned: string[] = [];
    switch (assetProps.asset_type) {
      case 'Web':
        classesAssigned.push('Application');
        break;
      case 'Mobile':
        classesAssigned.push('Application');
        break;
      case 'API':
        classesAssigned.push('ApplicationEndpoint');
        break;
      case 'External Network':
        classesAssigned.push('Network');
        break;
      case 'Cloud Config':
        classesAssigned.push('Configuration');
        break;
      case 'Internal Network':
        classesAssigned.push('Network');
        break;
      case 'Web+API':
        classesAssigned.push('Application');
        classesAssigned.push('ApplicationEndpoint');
        break;
      case 'Web+External Network':
        classesAssigned.push('Application');
        classesAssigned.push('Network');
        break;
      case 'Web+Mobile':
        classesAssigned.push('Application');
        break;
      default:
        classesAssigned.push('Application');
    }
    const assetEntity = await jobState.addEntity(
      createIntegrationEntity({
        entityData: {
          source: asset,
          assign: {
            _type: 'cobalt_asset',
            _class: classesAssigned,
            _key: assetProps.id,
            name: assetProps.title,
            displayName: assetProps.title,
            description: assetProps.description,
            assetType: assetProps.asset_type,
          },
        },
      }),
    );

    await jobState.addRelationship(
      createDirectRelationship({
        _class: RelationshipClass.HAS,
        from: accountEntity,
        to: assetEntity,
      }),
    );
  });
}

export const assetSteps: IntegrationStep<IntegrationConfig>[] = [
  {
    id: 'fetch-assets',
    name: 'Fetch Assets',
    entities: [
      {
        resourceName: 'Cobalt Asset',
        _type: 'cobalt_asset',
        _class: 'Application',
      },
      {
        resourceName: 'Cobalt Asset',
        _type: 'cobalt_asset',
        _class: 'ApplicationEndpoint',
      },
      {
        resourceName: 'Cobalt Asset',
        _type: 'cobalt_asset',
        _class: 'Network',
      },
      {
        resourceName: 'Cobalt Asset',
        _type: 'cobalt_asset',
        _class: 'Configuration',
      },
    ],
    relationships: [
      {
        _type: 'cobalt_account_has_asset',
        _class: RelationshipClass.HAS,
        sourceType: 'cobalt_account',
        targetType: 'cobalt_asset',
      },
    ],
    dependsOn: ['fetch-account'],
    executionHandler: fetchAssets,
  },
];
