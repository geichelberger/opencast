/*
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package org.opencastproject.graphql.execution;

import org.opencastproject.graphql.exception.GraphQLRuntimeException;
import org.opencastproject.graphql.exception.OpencastErrorType;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.CompletableFuture;

import graphql.GraphQLError;
import graphql.GraphqlErrorBuilder;
import graphql.execution.DataFetcherExceptionHandler;
import graphql.execution.DataFetcherExceptionHandlerParameters;
import graphql.execution.DataFetcherExceptionHandlerResult;
import graphql.execution.ResultPath;
import graphql.language.SourceLocation;

public class OpencastDataFetcherExceptionHandler implements DataFetcherExceptionHandler {

  private static final Logger logger = LoggerFactory.getLogger(OpencastDataFetcherExceptionHandler.class);

  @Override
  public CompletableFuture<DataFetcherExceptionHandlerResult> handleException(
      DataFetcherExceptionHandlerParameters handlerParameters) {
    return CompletableFuture.completedFuture(handleExceptionImpl(handlerParameters));
  }

  private DataFetcherExceptionHandlerResult handleExceptionImpl(
      DataFetcherExceptionHandlerParameters handlerParameters) {
    Throwable exception = unwrap(handlerParameters.getException());
    SourceLocation sourceLocation = handlerParameters.getSourceLocation();
    ResultPath path = handlerParameters.getPath();

    GraphQLError error;
    if (exception instanceof GraphQLRuntimeException) {
      GraphQLRuntimeException graphQLException = (GraphQLRuntimeException) exception;
      if (graphQLException.getErrorType() == OpencastErrorType.InternalError) {
        logger.error("Error while fetching {}", path, exception);
      }
      error = graphQLException;
    } else {
      // Unexpected exception: its message may contain internal details, so only log it
      logger.error("Unexpected error while fetching {}", path, exception);
      error = GraphqlErrorBuilder.newError()
          .message(GraphQLRuntimeException.INTERNAL_ERROR_MESSAGE)
          .path(path)
          .location(sourceLocation)
          .errorType(OpencastErrorType.InternalError)
          .build();
    }
    return DataFetcherExceptionHandlerResult.newResult().error(error).build();
  }

  /**
   * Called to unwrap an exception to a more suitable cause if required.
   *
   * @param exception the exception to unwrap
   *
   * @return the suitable exception
   */
  protected Throwable unwrap(Throwable exception) {
    if (exception.getCause() != null && exception instanceof RuntimeException) {
      if (exception.getCause() instanceof InvocationTargetException) {
        return ((InvocationTargetException) exception.getCause()).getTargetException();
      }
      return exception.getCause();
    }
    return exception;
  }

}
