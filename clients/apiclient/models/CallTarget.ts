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

import { HttpFile } from '../http/http';

export class CallTarget {
    /**
    * The contract name as HName (Hex)
    */
    'contractHName': string;
    /**
    * The function name as HName (Hex)
    */
    'functionHName': string;

    static readonly discriminator: string | undefined = undefined;

    static readonly attributeTypeMap: Array<{name: string, baseName: string, type: string, format: string}> = [
        {
            "name": "contractHName",
            "baseName": "contractHName",
            "type": "string",
            "format": "string"
        },
        {
            "name": "functionHName",
            "baseName": "functionHName",
            "type": "string",
            "format": "string"
        }    ];

    static getAttributeTypeMap() {
        return CallTarget.attributeTypeMap;
    }

    public constructor() {
    }
}

