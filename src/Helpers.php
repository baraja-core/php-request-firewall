<?php

declare(strict_types=1);

namespace Baraja\RequestFirewall;


final class Helpers
{

	/** @throws \Error */
	public function __construct()
	{
		throw new \Error('Class ' . get_class($this) . ' is static and cannot be instantiated.');
	}


	/**
	 * @return mixed[]
	 */
	public static function getAllInputParams(): array
	{
		$url = self::getCurrentUrl();
		$baseUrl = self::getBaseUrl();
		$path = $url !== null && $baseUrl !== null ? str_replace($baseUrl, '', $url) : '';

		return array_merge(self::safeGetParams($path), self::getBodyParams(self::getHttpMethod()));
	}


	/**
	 * Returns flattened array.
	 *
	 * @param mixed[] $arr
	 * @return mixed[]
	 */
	public static function flatten(array $arr, bool $preserveKeys = false): array
	{
		$res = [];
		$cb = $preserveKeys ? function ($v, $k) use (&$res): void {
			$res[$k] = $v;
		} : function ($v) use (&$res): void {
			$res[] = $v;
		};
		array_walk_recursive($arr, $cb);

		return $res;
	}


	public static function getCurrentUrl(): ?string
	{
		if (!isset($_SERVER['REQUEST_URI'], $_SERVER['HTTP_HOST'])) {
			return null;
		}

		return (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
			. '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
	}


	public static function getBaseUrl(): ?string
	{
		static $return;

		if ($return !== null) {
			return $return;
		}
		if (($currentUrl = self::getCurrentUrl()) !== null) {
			if (preg_match('/^(https?:\/\/.+)\/www\//', $currentUrl, $localUrlParser)) {
				$return = $localUrlParser[0];
			} elseif (preg_match('/^(https?:\/\/[^\/]+)/', $currentUrl, $publicUrlParser)) {
				$return = $publicUrlParser[1];
			}
		}
		if ($return !== null) {
			$return = rtrim($return, '/');
		}

		return $return;
	}


	/**
	 * Safe method for get parameters from query. This helper is for CLI mode and broken Ngnix mod rewriting.
	 *
	 * @param string $path
	 * @return mixed[]
	 */
	private static function safeGetParams(string $path): array
	{
		$return = (array) ($_GET ?? []);
		if ($return === [] && ($query = trim(explode('?', $path, 2)[1] ?? '')) !== '') {
			parse_str($query, $queryParams);
			foreach ($queryParams as $key => $value) {
				$return[$key] = $value;
			}
		}

		return $return;
	}


	/**
	 * @param string $method
	 * @return mixed[]
	 */
	private static function getBodyParams(string $method): array
	{
		if ($method !== 'GET' && $method !== 'DELETE') {
			$return = [];
			if (\count($_POST) === 1 && preg_match('/^\{.*\}$/', $post = array_keys($_POST)[0]) && is_array($json = json_decode($post, true)) === true) {
				foreach ($json as $key => $value) {
					$return[$key] = $value;
				}
				unset($_POST[$post]);
			} elseif (($input = (string) file_get_contents('php://input')) !== '' && $json = json_decode($input, true)) {
				foreach ($json as $key => $value) {
					$return[$key] = $value;
				}
			}

			return $return;
		}

		return [];
	}


	private static function getHttpMethod(): string
	{
		if (($method = $_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST'
			&& preg_match('#^[A-Z]+$#D', $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] ?? '')
		) {
			$method = $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'];
		}

		return $method ?: 'GET';
	}
}
