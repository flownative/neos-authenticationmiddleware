<?php
namespace Flownative\AuthenticationMiddleware;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Authentication\AuthenticationManagerInterface;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Context;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 *
 */
class AuthenticateTokens implements MiddlewareInterface
{
    /**
     * @Flow\Inject(lazy=false)
     * @var Context
     */
    protected $securityContext;

    /**
     * @Flow\Inject(lazy=false)
     * @var AuthenticationManagerInterface
     */
    protected $authenticationProviderManager;

    /**
     * @inheritDoc
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        /**
         * Silently trigger authentication for any token that can just be authenticated (e.g. valid JWTs)
         * This ensures we have role and account information available without explicitly asking for authentication everywhere.
         * For example EntityPrivileges currently never authenticate but rely on other code doing the authenticate call.
         */
        try {
            $this->authenticationProviderManager->authenticate();
        } catch (AuthenticationRequiredException $exception) {
        }
        return $handler->handle($request);
    }
}
