import {
  createDirectRelationship,
  createIntegrationEntity,
  IntegrationStep,
  IntegrationStepExecutionContext,
  RelationshipClass,
  IntegrationMissingKeyError,
  assignTags,
} from '@jupiterone/integration-sdk-core';

import { createAPIClient } from '../client';
import { IntegrationConfig } from '../types';
import { getVulnerabilityLink, getVulnerabilityNumber } from '../util';

export async function fetchFindings({
  instance,
  jobState,
}: IntegrationStepExecutionContext<IntegrationConfig>) {
  const apiClient = createAPIClient(instance.config);

  await apiClient.iterateFindings(async (finding) => {
    const findingProps = finding.resource;
    let openBoolean: boolean;
    findingProps.state === 'fixed'
      ? (openBoolean = false)
      : (openBoolean = true);

    // to derive the Finding webLink, we'll need pentest.weblink
    //can't have a Finding without an Assessment (pentest)
    const assessmentEntity = await jobState.findEntity(findingProps.pentest_id);
    if (!assessmentEntity) {
      throw new IntegrationMissingKeyError(
        `Expected Assessment with key to exist (key=${findingProps.pentest_id}) as part of Finding (key=${findingProps.id})`,
      );
    }
    // Example weblink about calculations below:
    // https://app.cobalt.io/test-org-api/test-asset-1-february-2021-pt5734/findings/1
    const orgWebLink: string = `${assessmentEntity.webLink}`;
    const lenToChop = 'brief'.length; //cut off the word brief from assessment (pentest) link
    const findingNum = findingProps.tag.split('_')[1]; //example of finding.tag is #PT5734_1
    const webLink = `${orgWebLink.substring(
      0,
      orgWebLink.length - lenToChop,
    )}findings/${findingNum}`;

    const findingEntity = await jobState.addEntity(
      createIntegrationEntity({
        entityData: {
          source: finding,
          assign: {
            _type: 'cobalt_finding',
            _class: 'Finding',
            _key: findingProps.id,
            cobaltHashtag: findingProps.tag,
            name: findingProps.title,
            displayName: findingProps.title,
            webLink: webLink,
            description: findingProps.description,
            category: 'Penetration Testing',
            typeCategory: findingProps.type_category,
            impact: JSON.stringify(findingProps.impact, null, 2), //required to be a string in J1 Finding
            severity: findingProps.severity, //required property in J1 Finding
            numericSeverity: findingProps.impact * 2, //required property in J1 Finding, normalized
            likelihood: findingProps.likelihood,
            state: findingProps.state,
            open: openBoolean, //required property in J1 Finding
            targets: findingProps.affected_targets, //.targets has a global mapping in J1
            proofOfConcept: findingProps.proof_of_concept,
            suggestedFix: findingProps.suggested_fix,
            prerequisites: findingProps.prerequisites,
            pentestId: findingProps.pentest_id, //value of pentest Assessment _key
            assetId: findingProps.asset_id, // value of asset _key (which could be class Application or something else)
          },
        },
      }),
    );

    if (findingProps.labels) {
      const labelArray: string[] = [];
      for (const someLabel in findingProps.labels) {
        labelArray.push(JSON.stringify(someLabel));
      } //because I don't have any data to determine if labels are strings or objects
      assignTags(findingEntity, labelArray);
    }

    await jobState.addRelationship(
      createDirectRelationship({
        _class: RelationshipClass.IDENTIFIED,
        from: assessmentEntity,
        to: findingEntity,
      }),
    );

    //we would like to tie Finding to a cobalt_asset, but the asset can be deleted or not relevant
    let assetEntity;
    if (findingProps.asset_id) {
      assetEntity = await jobState.findEntity(findingProps.asset_id);
    }
    if (assetEntity) {
      await jobState.addRelationship(
        createDirectRelationship({
          _class: RelationshipClass.HAS,
          from: assetEntity,
          to: findingEntity,
        }),
      );
    } //if assetEntity does not exist, just move on

    const vulnLink: string = getVulnerabilityLink(findingProps.description);
    if (!(vulnLink === 'none')) {
      //we have detected a link to a CVE or CWE in the description, so let's make a Vulnerability object
      const vulnNumber = getVulnerabilityNumber(vulnLink);
      const vulnerabilityEntity = await jobState.addEntity(
        createIntegrationEntity({
          entityData: {
            source: {
              name: vulnNumber,
              link: vulnLink,
            },
            assign: {
              _type: 'cobalt_vulnerability',
              _class: 'Vulnerability',
              _key: vulnNumber,
              name: vulnNumber,
              displayName: vulnNumber,
              category: 'application',
              webLink: vulnLink,
              severity: 'unknown',
              blocking: false,
              open: true,
              production: true,
              public: true,
            },
          },
        }),
      );

      await jobState.addRelationship(
        createDirectRelationship({
          _class: RelationshipClass.IS,
          from: findingEntity,
          to: vulnerabilityEntity,
        }),
      );
    }
  });
}

export const findingSteps: IntegrationStep<IntegrationConfig>[] = [
  {
    id: 'fetch-findings',
    name: 'Fetch Findings',
    entities: [
      {
        resourceName: 'Cobalt Finding',
        _type: 'cobalt_finding',
        _class: 'Finding',
        partial: true,
      },
      {
        resourceName: 'Cobalt Vulnerability',
        _type: 'cobalt_vulnerability',
        _class: 'Vulnerability',
        partial: true,
      },
    ],
    relationships: [
      {
        _type: 'cobalt_pentest_identified_finding',
        _class: RelationshipClass.IDENTIFIED,
        sourceType: 'cobalt_pentest',
        targetType: 'cobalt_finding',
      },
      {
        _type: 'cobalt_asset_has_finding',
        _class: RelationshipClass.HAS,
        sourceType: 'cobalt_asset',
        targetType: 'cobalt_finding',
      },
      {
        _type: 'cobalt_pentest_identified_vulnerability',
        _class: RelationshipClass.IDENTIFIED,
        sourceType: 'cobalt_pentest',
        targetType: 'cobalt_vulnerability',
      },
      {
        _type: 'cobalt_finding_is_vulnerability',
        _class: RelationshipClass.IS,
        sourceType: 'cobalt_finding',
        targetType: 'cobalt_vulnerability',
      },
    ],
    dependsOn: ['fetch-pentests'],
    executionHandler: fetchFindings,
  },
];
