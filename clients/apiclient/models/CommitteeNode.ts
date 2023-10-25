/**
 * Wasp API
 * REST API for the Wasp node
 *
 * OpenAPI spec version: 0
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

import { PeeringNodeStatusResponse } from '../models/PeeringNodeStatusResponse';
import { HttpFile } from '../http/http';

export class CommitteeNode {
    'accessAPI': string;
    'node': PeeringNodeStatusResponse;

    static readonly discriminator: string | undefined = undefined;

    static readonly attributeTypeMap: Array<{name: string, baseName: string, type: string, format: string}> = [
        {
            "name": "accessAPI",
            "baseName": "accessAPI",
            "type": "string",
            "format": "string"
        },
        {
            "name": "node",
            "baseName": "node",
            "type": "PeeringNodeStatusResponse",
            "format": ""
        }    ];

    static getAttributeTypeMap() {
        return CommitteeNode.attributeTypeMap;
    }

    public constructor() {
    }
}
