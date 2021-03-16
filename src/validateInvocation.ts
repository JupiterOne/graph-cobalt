import {
  IntegrationExecutionContext,
  IntegrationValidationError,
} from '@jupiterone/integration-sdk-core';

import { createAPIClient } from './client';
import { IntegrationConfig } from './types';

export default async function validateInvocation(
  context: IntegrationExecutionContext<IntegrationConfig>,
) {
  const { config } = context.instance;

  if (!config.apiKeyAuth) {
    throw new IntegrationValidationError('Config requires all of {apiKeyAuth}');
  }

  const apiClient = createAPIClient(config);
  await apiClient.verifyAuthentication();
}
