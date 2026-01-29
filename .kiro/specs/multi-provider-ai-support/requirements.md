# Requirements Document

## Introduction

This specification defines the requirements for adding OpenRouter and Local AI (Ollama) support to VISTA, expanding the AI provider options from 2 (OpenAI, Azure AI) to 4 providers. This enhancement will provide users with access to 600+ AI models, free tier options, privacy-focused local models, and significant cost savings.

## Glossary

- **VISTA**: The Burp Suite extension for AI-powered security testing
- **AI_Provider**: A service that provides AI model access (OpenAI, Azure AI, OpenRouter, Local AI)
- **OpenRouter**: A unified gateway API that provides access to 500+ AI models from 60+ providers
- **Local_AI**: Locally-hosted AI models running through Ollama
- **Ollama**: An open-source platform for running large language models locally
- **Context_Window**: The maximum number of tokens an AI model can process in a single request
- **API_Key**: Authentication credential for cloud-based AI providers
- **Base_URL**: The endpoint URL for API requests
- **Model_ID**: The identifier for a specific AI model
- **AIConfigManager**: The centralized configuration manager for AI settings in VISTA
- **AIService**: The interface that all AI provider implementations must follow
- **SettingsPanel**: The UI component where users configure AI providers

## Requirements

### Requirement 1: OpenRouter Provider Support

**User Story:** As a VISTA user, I want to use OpenRouter as my AI provider, so that I can access 500+ models from multiple providers through a single API key.

#### Acceptance Criteria

1. WHEN a user selects OpenRouter as the provider, THE System SHALL display OpenRouter-specific configuration fields
2. WHEN a user enters an OpenRouter API key and model ID, THE System SHALL validate the configuration
3. WHEN a user tests the OpenRouter connection, THE System SHALL send a test request and display the result
4. WHEN VISTA sends an analysis request, THE System SHALL route it to OpenRouter using the OpenAI-compatible API format
5. WHEN OpenRouter returns a response, THE System SHALL parse and display it correctly

### Requirement 2: Local AI Provider Support

**User Story:** As a VISTA user, I want to use locally-hosted AI models through Ollama, so that I can maintain data privacy and work offline without API costs.

#### Acceptance Criteria

1. WHEN a user selects Local AI as the provider, THE System SHALL display Local AI-specific configuration fields
2. WHEN a user enters a Local AI base URL and model name, THE System SHALL validate the configuration
3. WHEN a user tests the Local AI connection, THE System SHALL send a test request to the local Ollama instance
4. WHEN VISTA sends an analysis request, THE System SHALL route it to the local Ollama instance using the OpenAI-compatible API format
5. WHEN the local model returns a response, THE System SHALL parse and display it correctly

### Requirement 3: Provider Selection UI

**User Story:** As a VISTA user, I want to easily select and configure my preferred AI provider, so that I can switch between providers based on my needs.

#### Acceptance Criteria

1. WHEN a user opens the Settings panel, THE System SHALL display a provider dropdown with four options: OpenAI, Azure AI, OpenRouter, Local AI
2. WHEN a user selects a provider, THE System SHALL show only the relevant configuration fields for that provider
3. WHEN a user switches providers, THE System SHALL preserve the configuration for each provider separately
4. WHEN a user saves the configuration, THE System SHALL persist all provider settings to disk
5. WHEN VISTA starts, THE System SHALL load the last-used provider configuration

### Requirement 4: OpenRouter Configuration Fields

**User Story:** As a VISTA user, I want to configure OpenRouter with minimal effort, so that I can quickly start using it.

#### Acceptance Criteria

1. WHEN OpenRouter is selected, THE System SHALL display an API Key field
2. WHEN OpenRouter is selected, THE System SHALL display a Model ID field with a default value
3. WHEN OpenRouter is selected, THE System SHALL display a Base URL field with default value "https://openrouter.ai/api/v1"
4. WHEN a user enters an OpenRouter model ID, THE System SHALL accept any valid model identifier format
5. WHEN a user saves OpenRouter configuration, THE System SHALL validate that API Key and Model ID are not empty

### Requirement 5: Local AI Configuration Fields

**User Story:** As a VISTA user, I want to configure Local AI with clear guidance, so that I can successfully connect to my Ollama instance.

#### Acceptance Criteria

1. WHEN Local AI is selected, THE System SHALL display a Base URL field with default value "http://localhost:11434"
2. WHEN Local AI is selected, THE System SHALL display a Model Name field with a default value
3. WHEN Local AI is selected, THE System SHALL NOT display an API Key field
4. WHEN a user enters a Local AI model name, THE System SHALL accept any valid Ollama model identifier
5. WHEN a user saves Local AI configuration, THE System SHALL validate that Base URL and Model Name are not empty

### Requirement 6: OpenRouter Service Implementation

**User Story:** As a developer, I want an OpenRouter service implementation, so that VISTA can communicate with OpenRouter's API.

#### Acceptance Criteria

1. THE OpenRouterService SHALL implement the AIService interface
2. WHEN making API requests, THE OpenRouterService SHALL use the OpenAI-compatible chat completions endpoint
3. WHEN making API requests, THE OpenRouterService SHALL include the API key in the Authorization header
4. WHEN making API requests, THE OpenRouterService SHALL format messages in OpenAI-compatible JSON format
5. WHEN receiving responses, THE OpenRouterService SHALL parse the OpenAI-compatible response format

### Requirement 7: Local AI Service Implementation

**User Story:** As a developer, I want a Local AI service implementation, so that VISTA can communicate with Ollama instances.

#### Acceptance Criteria

1. THE LocalAIService SHALL implement the AIService interface
2. WHEN making API requests, THE LocalAIService SHALL use the OpenAI-compatible chat completions endpoint
3. WHEN making API requests, THE LocalAIService SHALL NOT include an Authorization header
4. WHEN making API requests, THE LocalAIService SHALL format messages in OpenAI-compatible JSON format
5. WHEN receiving responses, THE LocalAIService SHALL parse the OpenAI-compatible response format

### Requirement 8: Configuration Persistence

**User Story:** As a VISTA user, I want my provider configurations to be saved, so that I don't have to re-enter them every time I use VISTA.

#### Acceptance Criteria

1. WHEN a user saves configuration, THE System SHALL persist OpenRouter settings to the configuration file
2. WHEN a user saves configuration, THE System SHALL persist Local AI settings to the configuration file
3. WHEN VISTA starts, THE System SHALL load all provider configurations from the configuration file
4. WHEN a user switches providers, THE System SHALL remember the last-used provider
5. WHEN configuration is saved, THE System SHALL store provider-specific fields separately

### Requirement 9: Connection Testing

**User Story:** As a VISTA user, I want to test my AI provider connection, so that I can verify my configuration is correct before using VISTA features.

#### Acceptance Criteria

1. WHEN a user clicks "Test Connection" with OpenRouter configured, THE System SHALL send a test request to OpenRouter
2. WHEN a user clicks "Test Connection" with Local AI configured, THE System SHALL send a test request to the local Ollama instance
3. WHEN a connection test succeeds, THE System SHALL display a success message with the AI response
4. WHEN a connection test fails, THE System SHALL display an error message with the failure reason
5. WHEN a connection test is in progress, THE System SHALL display a loading indicator

### Requirement 10: Error Handling

**User Story:** As a VISTA user, I want clear error messages when something goes wrong, so that I can troubleshoot configuration issues.

#### Acceptance Criteria

1. WHEN OpenRouter returns an HTTP error, THE System SHALL display the error code and message
2. WHEN Local AI is unreachable, THE System SHALL display a connection error message
3. WHEN an API key is invalid, THE System SHALL display an authentication error message
4. WHEN a model ID is invalid, THE System SHALL display a model not found error message
5. WHEN a request times out, THE System SHALL display a timeout error message

### Requirement 11: Backward Compatibility

**User Story:** As an existing VISTA user, I want my current OpenAI or Azure AI configuration to continue working, so that I don't have to reconfigure anything after the update.

#### Acceptance Criteria

1. WHEN VISTA loads an existing configuration file, THE System SHALL correctly parse OpenAI settings
2. WHEN VISTA loads an existing configuration file, THE System SHALL correctly parse Azure AI settings
3. WHEN VISTA loads a configuration without provider field, THE System SHALL default to OpenAI
4. WHEN existing code calls AIConfigManager, THE System SHALL return the correct provider settings
5. WHEN existing features use AI services, THE System SHALL route requests to the configured provider

### Requirement 12: Model Recommendations

**User Story:** As a VISTA user, I want guidance on which models to use, so that I can choose appropriate models for security testing.

#### Acceptance Criteria

1. WHEN a user selects OpenRouter, THE System SHALL suggest a default free model with sufficient context window
2. WHEN a user selects Local AI, THE System SHALL suggest a default model with sufficient context window
3. WHEN a user hovers over the Model field, THE System SHALL display a tooltip with model recommendations
4. WHEN a user enters a model with insufficient context window, THE System SHALL display a warning
5. WHEN a user views the Settings panel, THE System SHALL display information about context window requirements
