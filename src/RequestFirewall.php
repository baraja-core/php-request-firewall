<?php

declare(strict_types=1);

namespace Baraja\RequestFirewall;


final class RequestFirewall
{

	/**
	 * This logic parses the current HTTP request. An \RuntimeException is thrown for unsafe calls.
	 */
	public function run(): void
	{
		if (PHP_SAPI === 'cli') {
			return;
		}

		if ($this->analyze() === true) {
			throw new \RuntimeException(
				'A security incident has been detected.' . "\n\n"
				. 'Request Firewall detected a security vulnerability and blocked the current request. '
				. 'Contact your server administrator for more information.'
			);
		}
	}


	public function analyze(): bool
	{
		foreach ($this->filterSafeParameters(Helpers::getAllInputParams()) as $param) {
			foreach ($this->getExactMatches() as $exactMatch) {
				if (strpos($param, $exactMatch) !== false) {
					return true;
				}
			}
			foreach ($this->getRegularRules() as $regularRule) {
				if (preg_match('/' . $regularRule . '/', $param)) {
					return true;
				}
			}
		}

		return false;
	}


	/**
	 * The method gets a list of all parameters and returns only the list of suspects as an array of strings.
	 *
	 * @param mixed[] $params
	 * @return string[]
	 */
	private function filterSafeParameters(array $params): array
	{
		$return = [];
		foreach (Helpers::flatten($params) as $param) {
			if (\is_string($param) === false) { // param is not string
				continue;
			}
			if (trim($param) === '') { // empty string or whitespaces only
				continue;
			}
			if (preg_match('#^[+-]?\d*[.]?\d+$#D', $param)) { // number
				continue;
			}
			if (preg_match('/[a-f0-9]{8}\-[a-f0-9]{4}\-4[a-f0-9]{3}\-(8|9|a|b)[a-f0-9]{3‌​}\-[a-f0-9]{12}/u', $param)) { // UUID
				continue;
			}
			$return[] = $param;
		}

		return $return;
	}


	/**
	 * @return string[]
	 */
	private function getRegularRules(): array
	{
		return [
			'<script.+alert',
		];
	}


	/**
	 * @return string[]
	 */
	private function getExactMatches(): array
	{
		return [
			'in_script;',
			'(SELECT CHAR(113)+CHAR(98)',
			'CASE WHEN (1209=1209) THEN CHAR(49)',
			'-- -',
			'`))-- -',
			'passthru(\'dir\')',
			'passthru(\'id\')',
			'../../../../../',
			'../../windows',
			'/etc/passwd',
			'\boot.ini',
			'/boot.ini',
			'<left_httpcs_get_13_id>',
		];
	}
}
