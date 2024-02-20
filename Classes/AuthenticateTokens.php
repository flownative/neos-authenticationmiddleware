<?php
namespace Flownative\AuthenticationMiddleware;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Authentication\AuthenticationManagerInterface;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Context;
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
        $tokensReadyForAuthentication = array_filter($this->securityContext->getAuthenticationTokens(), fn($token) => $token->getAuthenticationStatus() === TokenInterface::AUTHENTICATION_NEEDED);
        if (!empty($tokensReadyForAuthentication)) {
            $this->authenticationProviderManager->authenticate();
        }
        return $handler->handle($request);
    }
}
