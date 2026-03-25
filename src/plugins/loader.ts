import { readFileSync, existsSync } from "fs";
import { join } from "path";
import type { Scanner } from "../types";
import type { MimirPluginConfig, PluginConfig } from "./types";
import { PARSER_PRESETS } from "./types";
import { CliScanner } from "./cli-scanner";
import { logger } from "../logger";

const CONFIG_FILES = [".mimir.json", ".mimir.config.json", "mimir.config.json"];

/**
 * Load plugin configuration from file or environment
 */
export function loadPluginConfig(targetDir: string): MimirPluginConfig | null {
  // Check for config file
  for (const filename of CONFIG_FILES) {
    const configPath = join(targetDir, filename);
    if (existsSync(configPath)) {
      try {
        const content = readFileSync(configPath, "utf-8");
        return JSON.parse(content) as MimirPluginConfig;
      } catch (err) {
        logger.error(`Failed to load config from ${configPath}`, err);
      }
    }
  }

  // Check for environment variable
  const envConfig = process.env["MIMIR_PLUGINS_CONFIG"];
  if (envConfig) {
    try {
      return JSON.parse(envConfig) as MimirPluginConfig;
    } catch (err) {
      logger.error("Failed to parse MIMIR_PLUGINS_CONFIG", err);
    }
  }

  return null;
}

/**
 * Create scanner instances from plugin config
 */
export function createPluginScanners(config: MimirPluginConfig): Scanner[] {
  const scanners: Scanner[] = [];

  for (const pluginConfig of config.plugins ?? []) {
    // Merge with preset if using a known tool
    const preset = PARSER_PRESETS[pluginConfig.name.toLowerCase()];
    const mergedConfig: PluginConfig = {
      ...preset,
      ...pluginConfig,
      parser: {
        ...preset?.parser,
        ...pluginConfig.parser,
        fieldMapping: {
          ...preset?.parser?.fieldMapping,
          ...pluginConfig.parser?.fieldMapping,
        },
      },
    } as PluginConfig;

    scanners.push(new CliScanner(mergedConfig));
  }

  return scanners;
}

/**
 * Get a preset configuration for a known tool
 */
export function getPreset(name: string): Partial<PluginConfig> | undefined {
  return PARSER_PRESETS[name.toLowerCase()];
}

/**
 * List all available presets
 */
export function listPresets(): string[] {
  return Object.keys(PARSER_PRESETS);
}
