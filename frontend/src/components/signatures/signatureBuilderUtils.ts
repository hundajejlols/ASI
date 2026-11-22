import type {
  Severity,
  SignatureDraft,
  SignatureItem,
  SignatureMatchType,
  SignaturePortable,
} from '../../types';

export type HeaderOperator = 'exists' | 'contains' | 'equals' | 'starts_with' | 'version';
export type HtmlBuilderMode = 'phrases' | 'meta_generator';
export type FooterBuilderMode = 'app_version' | 'phrases';
export type PathBodyMode = 'any' | 'phrases';

export interface VisualBuilderState {
  // header
  headerName: string;
  headerOp: HeaderOperator;
  headerValue: string;
  // cookie
  cookieName: string;
  // favicon_hash
  faviconHash: string;
  // html_fragment
  htmlMode: HtmlBuilderMode;
  htmlPhrases: string;
  htmlMetaCms: string;
  // footer_version
  footerMode: FooterBuilderMode;
  footerApp: string;
  footerPhrases: string;
  // path_probe
  probePath: string;
  expectedStatus: string; // '' = dowolny 2xx/3xx
  pathBodyMode: PathBodyMode;
  pathPhrases: string;
  // wspólne
  caseInsensitive: boolean;
}

export const INITIAL_BUILDER_STATE: VisualBuilderState = {
  headerName: 'X-Powered-By',
  headerOp: 'exists',
  headerValue: '',
  cookieName: 'PHPSESSID',
  faviconHash: '',
  htmlMode: 'phrases',
  htmlPhrases: 'phpmyadmin, adminer',
  htmlMetaCms: '',
  footerMode: 'app_version',
  footerApp: '',
  footerPhrases: '',
  probePath: '/admin',
  expectedStatus: '200',
  pathBodyMode: 'phrases',
  pathPhrases: 'admin, dashboard, login',
  caseInsensitive: true,
};

export interface MatchTypeMeta {
  type: SignatureMatchType;
  label: string;
  shortDesc: string;
  passiveHint: string;
}

export const MATCH_TYPE_META: MatchTypeMeta[] = [
  {
    type: 'header',
    label: 'Nagłówek HTTP',
    shortDesc: 'Wykrywa obecność lub wartość nagłówka (np. Server, X-Powered-By)',
    passiveHint: 'Dopasowywane pasywnie do nagłówków odpowiedzi HTTP',
  },
  {
    type: 'cookie',
    label: 'Ciasteczko',
    shortDesc: 'Szuka charakterystycznej nazwy ciasteczka sesyjnego',
    passiveHint: 'Dopasowanie podciągu nazwy ciasteczka (bez rozróżniania wielkości liter)',
  },
  {
    type: 'favicon_hash',
    label: 'Favicon MMH3',
    shortDesc: 'Dokładny fingerprint ikony (standard Shodan MurmurHash3)',
    passiveHint: 'Idealne do wykrywania konkretnych paneli, routerów i CMS-ów',
  },
  {
    type: 'html_fragment',
    label: 'Fragment HTML',
    shortDesc: 'Wykrywa frazy, tagi meta generator lub podpisy CMS w treści HTML',
    passiveHint: 'Analizuje pobrany pasywnie kod strony głównej',
  },
  {
    type: 'footer_version',
    label: 'Wersja w stopce',
    shortDesc: 'Analizuje sekcję <footer> lub końcówkę HTML pod kątem wersji',
    passiveHint: 'Wykrywa np. "Powered by Moodle v4.3" lub "LegacyCMS v1.4.2"',
  },
  {
    type: 'path_probe',
    label: 'Sonda ścieżki GET',
    shortDesc: 'Pasywne GET względnej ścieżki (np. /admin, /metrics) z anty-soft-404',
    passiveHint: 'Wyłącznie bezpieczne GET bez logowania i bez exploitów',
  },
];

export const HEADER_SUGGESTIONS = [
  'Server',
  'X-Powered-By',
  'X-Generator',
  'X-Environment',
  'WWW-Authenticate',
  'X-AspNet-Version',
  'X-Drupal-Cache',
  'X-Jenkins',
];

export const COOKIE_SUGGESTIONS = [
  'PHPSESSID',
  'JSESSIONID',
  'wordpress_',
  'grafana_session',
  'i_like_gitea',
  '_gitlab_session',
  'csrftoken',
  'KEYCLOAK_SESSION',
];

export const PATH_SUGGESTIONS = [
  '/admin',
  '/login',
  '/version',
  '/metrics',
  '/swagger',
  '/api-docs',
  '/actuator/health',
  '/robots.txt',
  '/wp-login.php',
  '/dashboard/',
];

export interface SignaturePreset {
  id: string;
  label: string;
  name: string;
  description: string;
  severity: Severity;
  match_type: SignatureMatchType;
  state: Partial<VisualBuilderState>;
}

export const SIGNATURE_PRESETS: SignaturePreset[] = [
  {
    id: 'header-x-env',
    label: 'Nagłówek Staging/Dev',
    name: 'Staging Environment Header (X-Environment)',
    description: 'Wykrywa nagłówek X-Environment wskazujący na środowisko testowe/staging',
    severity: 'low',
    match_type: 'header',
    state: {
      headerName: 'X-Environment',
      headerOp: 'contains',
      headerValue: 'staging',
      caseInsensitive: true,
    },
  },
  {
    id: 'header-server-ver',
    label: 'Wersja serwera HTTP',
    name: 'Exposed Server Version (nginx)',
    description: 'Wykrywa ujawnienie numeru wersji serwera nginx w nagłówku Server',
    severity: 'info',
    match_type: 'header',
    state: {
      headerName: 'Server',
      headerOp: 'version',
      headerValue: 'nginx',
      caseInsensitive: true,
    },
  },
  {
    id: 'cookie-grafana',
    label: 'Ciasteczko Grafana',
    name: 'Grafana Session Cookie',
    description: 'Wykrywa instancję Grafana na podstawie ciasteczka grafana_session',
    severity: 'info',
    match_type: 'cookie',
    state: {
      cookieName: 'grafana_session',
    },
  },
  {
    id: 'path-metrics',
    label: 'Prometheus /metrics',
    name: 'Exposed Prometheus Metrics (/metrics)',
    description: 'Pasywne sprawdzenie GET niezabezpieczonego endpointu metryk Prometheus',
    severity: 'medium',
    match_type: 'path_probe',
    state: {
      probePath: '/metrics',
      expectedStatus: '200',
      pathBodyMode: 'phrases',
      pathPhrases: '# HELP, # TYPE, process_cpu',
      caseInsensitive: false,
    },
  },
  {
    id: 'path-swagger',
    label: 'Swagger / OpenAPI',
    name: 'Exposed Swagger UI (/swagger)',
    description: 'Pasywne sprawdzenie GET publicznie dostępnej dokumentacji API Swagger',
    severity: 'low',
    match_type: 'path_probe',
    state: {
      probePath: '/swagger',
      expectedStatus: '200',
      pathBodyMode: 'phrases',
      pathPhrases: 'swagger, openapi',
      caseInsensitive: true,
    },
  },
  {
    id: 'html-meta-cms',
    label: 'Meta Generator CMS',
    name: 'WordPress Meta Generator Tag',
    description: 'Wykrywa tag <meta name="generator"> ujawniający CMS WordPress',
    severity: 'low',
    match_type: 'html_fragment',
    state: {
      htmlMode: 'meta_generator',
      htmlMetaCms: 'WordPress',
      caseInsensitive: true,
    },
  },
  {
    id: 'footer-app-ver',
    label: 'Wersja w stopce HTML',
    name: 'LegacyCMS Footer Version',
    description: 'Wykrywa numer wersji aplikacji LegacyCMS w stopce HTML',
    severity: 'info',
    match_type: 'footer_version',
    state: {
      footerMode: 'app_version',
      footerApp: 'LegacyCMS',
      caseInsensitive: true,
    },
  },
];

export function escapeRegex(raw: string): string {
  return raw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function splitPhrases(raw: string): string[] {
  return raw
    .split(/[\n,]/)
    .map((p) => p.trim())
    .filter(Boolean);
}

function buildPhrasesRegex(raw: string, caseInsensitive: boolean): string {
  const parts = splitPhrases(raw).map(escapeRegex);
  if (parts.length === 0) return '';
  const prefix = caseInsensitive ? '(?i)' : '';
  if (parts.length === 1) return `${prefix}${parts[0]}`;
  return `${prefix}(${parts.join('|')})`;
}

export function buildPatternFromVisual(
  matchType: SignatureMatchType,
  state: VisualBuilderState
): string {
  const ci = state.caseInsensitive ? '(?i)' : '';

  switch (matchType) {
    case 'header': {
      const hName = state.headerName.trim();
      if (!hName) return '';
      const escName = escapeRegex(hName);
      const val = state.headerValue.trim();
      switch (state.headerOp) {
        case 'exists':
          return `${ci}^${escName}:\\s*.+`;
        case 'contains':
          return val ? `${ci}^${escName}:\\s*.*${escapeRegex(val)}` : `${ci}^${escName}:\\s*.+`;
        case 'equals':
          return val ? `${ci}^${escName}:\\s*${escapeRegex(val)}$` : `${ci}^${escName}:\\s*.+`;
        case 'starts_with':
          return val ? `${ci}^${escName}:\\s*${escapeRegex(val)}` : `${ci}^${escName}:\\s*.+`;
        case 'version':
          return val
            ? `${ci}^${escName}:\\s*.*${escapeRegex(val)}[/\\s]v?\\d+\\.\\d+`
            : `${ci}^${escName}:\\s*\\S+/\\d+\\.\\d+`;
      }
    }
    case 'cookie':
      return state.cookieName.trim();
    case 'favicon_hash':
      return state.faviconHash.trim();
    case 'html_fragment': {
      if (state.htmlMode === 'meta_generator') {
        const cms = state.htmlMetaCms.trim();
        if (cms) {
          return `${ci}<meta[^>]+name=["']generator["'][^>]+content=["'][^"']*${escapeRegex(cms)}[^"']*["']`;
        }
        return `${ci}<meta[^>]+name=["']generator["'][^>]+content=["'][^"']+\\d+\\.\\d+[^"']*["']`;
      }
      return buildPhrasesRegex(state.htmlPhrases, state.caseInsensitive);
    }
    case 'footer_version': {
      if (state.footerMode === 'app_version') {
        const app = state.footerApp.trim();
        if (app) {
          return `${ci}${escapeRegex(app)}\\s+v?\\d+\\.\\d+(\\.\\d+)?`;
        }
        return `${ci}(powered by|version|ver\\.?)\\s+[a-z0-9._-]+\\s+v?\\d+\\.\\d+(\\.\\d+)?`;
      }
      return buildPhrasesRegex(state.footerPhrases, state.caseInsensitive);
    }
    case 'path_probe': {
      if (state.pathBodyMode === 'any') return '';
      return buildPhrasesRegex(state.pathPhrases, state.caseInsensitive);
    }
  }
}

function unescapeSimple(escaped: string): string {
  return escaped.replace(/\\([.*+?^${}()|[\]\\])/g, '$1');
}

function isSimpleEscapedLiteral(part: string): boolean {
  // Akceptujemy brak niezescapowanych metaznaków regexa
  const stripped = part.replace(/\\([.*+?^${}()|[\]\\])/g, '');
  return !/[.*+?^${}()|[\]\\]/.test(stripped);
}

/**
 * Próbuje zdekodować istniejącą sygnaturę do pól kreatora wizualnego.
 * Jeśli regex jest ręczny/złożony, zwraca canUseVisual = false, aby nie utracić wzorca podczas edycji.
 */
export function parseSignatureToVisual(sig: SignatureItem): {
  state: VisualBuilderState;
  canUseVisual: boolean;
} {
  const base: VisualBuilderState = { ...INITIAL_BUILDER_STATE };
  const pat = (sig.pattern || '').trim();

  if (sig.match_type === 'cookie') {
    return { state: { ...base, cookieName: pat }, canUseVisual: true };
  }
  if (sig.match_type === 'favicon_hash') {
    return { state: { ...base, faviconHash: pat }, canUseVisual: true };
  }
  if (sig.match_type === 'path_probe') {
    base.probePath = sig.probe_path || '/admin';
    base.expectedStatus = sig.expected_status ? String(sig.expected_status) : '';
    if (!pat) {
      return { state: { ...base, pathBodyMode: 'any', pathPhrases: '' }, canUseVisual: true };
    }
    const ci = pat.startsWith('(?i)');
    const body = ci ? pat.slice(4) : pat;
    const inner = body.startsWith('(') && body.endsWith(')') ? body.slice(1, -1) : body;
    const parts = inner.split('|');
    if (parts.length > 0 && parts.every(isSimpleEscapedLiteral)) {
      return {
        state: {
          ...base,
          caseInsensitive: ci,
          pathBodyMode: 'phrases',
          pathPhrases: parts.map(unescapeSimple).join(', '),
        },
        canUseVisual: true,
      };
    }
    return { state: base, canUseVisual: false };
  }
  if (sig.match_type === 'header') {
    const ci = pat.startsWith('(?i)');
    const body = ci ? pat.slice(4) : pat;
    const mExists = body.match(/^\^([A-Za-z0-9_-]+):\\s\*\.\+$/);
    if (mExists) {
      return {
        state: { ...base, headerName: mExists[1], headerOp: 'exists', headerValue: '', caseInsensitive: ci },
        canUseVisual: true,
      };
    }
    const mContains = body.match(/^\^([A-Za-z0-9_-]+):\\s\*\.\*(.+)$/);
    if (mContains && isSimpleEscapedLiteral(mContains[2])) {
      return {
        state: {
          ...base,
          headerName: mContains[1],
          headerOp: 'contains',
          headerValue: unescapeSimple(mContains[2]),
          caseInsensitive: ci,
        },
        canUseVisual: true,
      };
    }
    const mEquals = body.match(/^\^([A-Za-z0-9_-]+):\\s\*(.+)\$$/);
    if (mEquals && isSimpleEscapedLiteral(mEquals[2])) {
      return {
        state: {
          ...base,
          headerName: mEquals[1],
          headerOp: 'equals',
          headerValue: unescapeSimple(mEquals[2]),
          caseInsensitive: ci,
        },
        canUseVisual: true,
      };
    }
    const mVerGeneric = body.match(/^\^([A-Za-z0-9_-]+):\\s\*\\S\+\/\\d\+\\\.\\d\+$/);
    if (mVerGeneric) {
      return {
        state: { ...base, headerName: mVerGeneric[1], headerOp: 'version', headerValue: '', caseInsensitive: ci },
        canUseVisual: true,
      };
    }
    return { state: base, canUseVisual: false };
  }
  return { state: base, canUseVisual: false };
}

export function applyDraftToVisual(draft: SignatureDraft): {
  state: VisualBuilderState;
  useAdvanced: boolean;
} {
  const base: VisualBuilderState = { ...INITIAL_BUILDER_STATE };
  if (draft.match_type === 'header') {
    if (draft.header_name) {
      return {
        state: {
          ...base,
          headerName: draft.header_name,
          headerOp: draft.header_op || (draft.header_value ? 'contains' : 'exists'),
          headerValue: draft.header_value || '',
          caseInsensitive: true,
        },
        useAdvanced: false,
      };
    }
    return { state: base, useAdvanced: Boolean(draft.pattern) };
  }
  if (draft.match_type === 'cookie') {
    return {
      state: { ...base, cookieName: draft.cookie_name || draft.pattern || '' },
      useAdvanced: false,
    };
  }
  if (draft.match_type === 'favicon_hash') {
    return {
      state: { ...base, faviconHash: draft.favicon_hash || draft.pattern || '' },
      useAdvanced: false,
    };
  }
  if (draft.match_type === 'path_probe') {
    return {
      state: {
        ...base,
        probePath: draft.probe_path || '/admin',
        expectedStatus: draft.expected_status ? String(draft.expected_status) : '200',
        pathBodyMode: draft.pattern ? 'phrases' : 'any',
        pathPhrases: draft.pattern || '',
      },
      useAdvanced: false,
    };
  }
  return { state: base, useAdvanced: Boolean(draft.pattern) };
}

export function getDefaultSampleForType(matchType: SignatureMatchType): {
  headers: string;
  cookies: string;
  html: string;
  statusCode: string;
  faviconHash: string;
} {
  switch (matchType) {
    case 'header':
      return {
        headers: 'Server: nginx/1.27.2\nX-Powered-By: PHP/7.4.33\nX-Environment: staging',
        cookies: '',
        html: '',
        statusCode: '200',
        faviconHash: '',
      };
    case 'cookie':
      return {
        headers: '',
        cookies: 'PHPSESSID, csrftoken, grafana_session',
        html: '',
        statusCode: '200',
        faviconHash: '',
      };
    case 'favicon_hash':
      return {
        headers: '',
        cookies: '',
        html: '',
        statusCode: '200',
        faviconHash: '-1986957532',
      };
    case 'html_fragment':
      return {
        headers: '',
        cookies: '',
        html: '<html><head><meta name="generator" content="WordPress 6.4" /></head><body><h1>Admin Panel</h1></body></html>',
        statusCode: '200',
        faviconHash: '',
      };
    case 'footer_version':
      return {
        headers: '',
        cookies: '',
        html: '<html><body><footer>Powered by LegacyCMS v1.4.2 | Environment: staging</footer></body></html>',
        statusCode: '200',
        faviconHash: '',
      };
    case 'path_probe':
      return {
        headers: '',
        cookies: '',
        html: '<html><head><title>Admin Control Panel</title></head><body><h1>Restricted administrative dashboard</h1></body></html>',
        statusCode: '200',
        faviconHash: '',
      };
  }
}

export function toPortableSignature(sig: SignatureItem): SignaturePortable {
  return {
    name: sig.name,
    description: sig.description,
    severity: sig.severity,
    match_type: sig.match_type,
    pattern: sig.pattern,
    probe_path: sig.probe_path,
    expected_status: sig.expected_status,
    is_enabled: sig.is_enabled,
  };
}

export const EXAMPLE_IMPORT_JSON = JSON.stringify(
  {
    schema_version: '1.0',
    signatures: [
      {
        name: 'Staging Environment Header',
        description: 'Wykrywa nagłówek X-Environment dla środowisk testowych/staging',
        severity: 'low',
        match_type: 'header',
        pattern: '(?i)^X-Environment:\\s*.*(staging|dev|test|uat)',
        is_enabled: true,
      },
      {
        name: 'Grafana Session Cookie',
        description: 'Wykrywa ciasteczko sesyjne panelu Grafana',
        severity: 'info',
        match_type: 'cookie',
        pattern: 'grafana_session',
        is_enabled: true,
      },
      {
        name: 'Exposed Prometheus Metrics (/metrics)',
        description: 'Pasywne GET /metrics sprawdzające ekspozycję metryk Prometheus',
        severity: 'medium',
        match_type: 'path_probe',
        probe_path: '/metrics',
        expected_status: 200,
        pattern: '(# HELP|# TYPE)',
        is_enabled: true,
      },
    ],
  },
  null,
  2
);
