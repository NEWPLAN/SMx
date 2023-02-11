/*************************************************************************
      > File Name: sm3.h
      > Author:NEWPLAN
      > E-mail:newplan001@163.com
      > Created Time: Thu Apr 13 23:55:50 2017
************************************************************************/

#include <stdint.h>

#ifndef XYSSL_SM3_H
#define XYSSL_SM3_H


/**
 * \brief          SM3 context structure
 */
typedef struct
{
      uint32_t total[2];     /*!< number of bytes processed  */
      uint32_t state[8];     /*!< intermediate digest state  */
      uint8_t buffer[64];   /*!< data block being processed */

      uint8_t ipad[64];     /*!< HMAC: inner padding        */
      uint8_t opad[64];     /*!< HMAC: outer padding        */

}
sm3_context;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          SM3 context setup
 *
 * \param ctx      context to be initialized
 */
void sm3_starts( sm3_context *ctx );

/**
 * \brief          SM3 process buffer
 *
 * \param ctx      SM3 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void sm3_update( sm3_context *ctx, uint8_t *input, int ilen );

/**
 * \brief          SM3 final digest
 *
 * \param ctx      SM3 context
 */
void sm3_finish( sm3_context *ctx, uint8_t output[32] );

/**
 * \brief          Output = SM3( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   SM3 checksum result
 */
void sm3( uint8_t *input, int ilen,
          uint8_t output[32]);

/**
 * \brief          Output = SM3( file contents )
 *
 * \param path     input file name
 * \param output   SM3 checksum result
 *
 * \return         0 if successful, 1 if fopen failed,
 *                 or 2 if fread failed
 */
int sm3_file( char *path, uint8_t output[32] );

/**
 * \brief          SM3 HMAC context setup
 *
 * \param ctx      HMAC context to be initialized
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 */
void sm3_hmac_starts( sm3_context *ctx, uint8_t *key, int keylen);

/**
 * \brief          SM3 HMAC process buffer
 *
 * \param ctx      HMAC context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void sm3_hmac_update( sm3_context *ctx, uint8_t *input, int ilen );

/**
 * \brief          SM3 HMAC final digest
 *
 * \param ctx      HMAC context
 * \param output   SM3 HMAC checksum result
 */
void sm3_hmac_finish( sm3_context *ctx, uint8_t output[32] );

/**
 * \brief          Output = HMAC-SM3( hmac key, input buffer )
 *
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   HMAC-SM3 result
 */
void sm3_hmac( uint8_t *key, int keylen,
               uint8_t *input, int ilen,
               uint8_t output[32] );


#ifdef __cplusplus
}
#endif

#endif /* sm3.h */
