const fs = require('fs-extra');
const path = require('path');

const Cloudformation = require('./aws-utils/aws-cfn');
const { S3 } = require('./aws-utils/aws-s3');
const { loadConfigurationForEnv } = require('./configuration-manager');
const { deleteEnv } = require('./amplify-service-manager');
const { S3BackendZipFileName, ProviderName } = require('./constants');
const { downloadZip, extractZip } = require('./zip-util');

async function run(context, envName, deleteS3) {
  const awsConfig = await loadConfigurationForEnv(context, envName);
  const cfn = await new Cloudformation(context, null, awsConfig);
  const s3 = await S3.getInstance(context, {});
  let removeBucket = false;
  let deploymentBucketName;

  if (deleteS3) {
    const projectDetails = context.amplify.getProjectDetails();
    deploymentBucketName = projectDetails.teamProviderInfo[envName][ProviderName].DeploymentBucketName;
    if (await s3.ifBucketExists(deploymentBucketName)) {
      const amplifyDir = context.amplify.pathManager.getAmplifyDirPath();
      const tempDir = path.join(amplifyDir, envName, '.temp');
      const storageCategoryBucketName = await getStorageCategoryBucketNameFromCloud(context, envName, s3, tempDir);

      fs.removeSync(tempDir);

      if (storageCategoryBucketName) {
        await s3.emptyS3Bucket(storageCategoryBucketName);
      }

      removeBucket = true;
    } else {
      context.print.info(
        `Unable to remove env: ${envName} because deployment bucket ${deploymentBucketName} does not exist or has been deleted.`,
      );
    }
  }

  await cfn.deleteResourceStack(envName);
  await deleteEnv(context, envName, awsConfig);

  if (removeBucket && deploymentBucketName) {
    await s3.deleteS3Bucket(deploymentBucketName);
  }
}

async function getStorageCategoryBucketNameFromCloud(context, envName, s3, tempDir) {
  const sourceZipFile = await downloadZip(s3, tempDir, S3BackendZipFileName, envName);
  const unZippedDir = await extractZip(tempDir, sourceZipFile);
  const amplifyMeta = context.amplify.readJsonFile(`${unZippedDir}/amplify-meta.json`);
  const storage = amplifyMeta['storage'] || {};

  // filter out imported buckets as we cannot touch those.
  const s3Storage = Object.keys(storage).filter(r => storage[r].service === 'S3' && storage[r].serviceType !== 'imported');

  if (!s3Storage.length) {
    return;
  }

  const fStorageName = s3Storage[0];

  return storage[fStorageName].output.BucketName;
}

module.exports = {
  run,
};
