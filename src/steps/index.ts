import { accountSteps } from './account';
import { pentestSteps } from './pentests';
import { findingSteps } from './findings';
import { assetSteps } from './assets';

const integrationSteps = [
  ...accountSteps,
  ...assetSteps,
  ...pentestSteps,
  ...findingSteps,
];

export { integrationSteps };
