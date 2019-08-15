import {
  defaultFieldResolver,
  GraphQLField,
  GraphQLInterfaceType,
  GraphQLObjectType,
  GraphQLSchema,
} from 'graphql';
import { buildSchemaFromTypeDefinitions, forEachField } from 'graphql-tools';
import { AmplifyAppSyncSimulator } from '../..';
import { AmplifyAppSyncSimulatorRequestContext } from '../../type-definition';
import { Unauthorized } from '../../velocity/util';
import AppSyncSimulatorDirectiveBase from './directive-base';

const AUTH_DIRECTIVES = {
  aws_api_key: 'directive @aws_api_key on FIELD_DEFINITION | OBJECT',
  aws_iam: 'directive @aws_iam on FIELD_DEFINITION | OBJECT',
  aws_oidc: 'directive @aws_oidc on FIELD_DEFINITION | OBJECT',
  aws_cognito_user_pools: 'directive @aws_auth(cognito_groups: [String!]!) on FIELD_DEFINITION',
};
export class AwsAuth extends AppSyncSimulatorDirectiveBase {
  private authMapping;
  static typeDefinitions: string = Object.values(AUTH_DIRECTIVES).join('\n');

  visitFieldDefinition(
    field: GraphQLField<any, any>,
    details: {
      objectType: GraphQLObjectType | GraphQLInterfaceType;
    }
  ) {}

  visitObject(object: GraphQLObjectType) {}
}

function getResolver(resolverMap, typeName, fieldName) {
  if (resolverMap && resolverMap[typeName] && resolverMap[typeName][fieldName]) {
    return resolverMap[typeName][fieldName];
  }
  return false;
}
function getAuthDirectiveForField(
  schema: GraphQLSchema,
  field,
  typeName: string,
  simulator: AmplifyAppSyncSimulator
) {
  const authDirectiveNames = Object.keys(AUTH_DIRECTIVES);
  const fieldDirectives = field.astNode.directives.map(d => d.name.value);
  const parentField = schema.getType(typeName);
  const fieldAuthDirectives = fieldDirectives.filter(d => authDirectiveNames.includes(d));
  const parentAuthDirectives = parentField.astNode.directives
    .map(d => d.name.value)
    .filter(d => authDirectiveNames.includes(d));
  return fieldAuthDirectives.length
    ? fieldAuthDirectives
    : parentAuthDirectives.length
    ? parentAuthDirectives
    : [simulator.appSyncConfig.defaultAuthenticationType.authenticationType];
}

export function generateAuthResolvers(
  typeDef,
  existingResolvers,
  simulator: AmplifyAppSyncSimulator
) {
  const schema = buildSchemaFromTypeDefinitions(typeDef);
  const newResolverMap = {};
  forEachField(schema, (field, typeName, fieldName) => {
    const fieldResolver = getResolver(existingResolvers, typeName, fieldName);
    const allowedAuthTypes = getAuthDirectiveForField(schema, field, typeName, simulator);
    const newResolver = (root, args, ctx: AmplifyAppSyncSimulatorRequestContext, info) => {
      // need to add support for cognito:groups
      if (!allowedAuthTypes.includes(ctx.requestAuthorizationMode)) {
        const err = new Unauthorized(`Not Authorized to access ${fieldName} on type ${typeName}`);
        throw err;
      }
      return (fieldResolver || defaultFieldResolver)(root, args, ctx, info);
    };
    if (!newResolverMap[typeName]) {
      newResolverMap[typeName] = {};
    }
    newResolverMap[typeName][fieldName] = newResolver;
  });
  return newResolverMap;
}
