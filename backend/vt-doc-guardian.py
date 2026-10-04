#!/usr/bin/env python3
"""
VirusTotal Document Scanner v3.3
================================
Verifica documentos em um diretório (e subpastas) usando a API do VirusTotal, com:
- Validação rigorosa de tipos MIME
- Detecção de malware e greyware
- Análise recursiva opcional em subpastas
- Gestão inteligente de arquivos ignorados (quarentena)

Principais melhorias na v3.3:
- Sistema de quarentena para arquivos ignorados
- Relatório detalhado com histórico de ações
- Preservação da estrutura de diretórios na quarentena
- Tratamento seguro de permissões durante movimentação

Requisitos:
- python-magic (para detecção MIME)
- python-dotenv (para variáveis de ambiente)
- requests (para comunicação com API)

Como usar:
1. Crie arquivo .env com: VT_API_KEY=sua_chave_aqui
2. Execute: python3 scanner.py
3. Informe o diretório e se deseja incluir subpastas
4. Decida o destino dos arquivos ignorados
"""
import csv
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from shutil import move

import magic
import requests
from dotenv import load_dotenv
from requests.exceptions import RequestException

# Carrega variáveis de ambiente do .env
load_dotenv()

# Tipos suportados pelo VirusTotal (com mapeamento MIME preciso)
SUPPORTED_MIME = {
    '.pdf': 'application/pdf',
    '.ppt': 'application/vnd.ms-powerpoint',
    '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    '.pps': 'application/vnd.ms-powerpoint',
    '.ppsx': 'application/vnd.openxmlformats-officedocument.presentationml.slideshow',
    '.odp': 'application/vnd.oasis.opendocument.presentation'
}

SUPPORTED_EXTENSIONS = {ext: doc_type for ext, doc_type in {
    '.pdf': "PDF Document",
    '.ppt': "PowerPoint 97-2003",
    '.pptx': "PowerPoint 2007+",
    '.pps': "PowerPoint Slide Show",
    '.ppsx': "PowerPoint Slide Show XML",
    '.odp': "OpenDocument Presentation"
}.items() if ext in SUPPORTED_MIME}

MIN_FILE_SIZE = 512  # 512 bytes
MAX_FILE_SIZE = 32 * 1024 * 1024  # 32MB
API_URL = "https://www.virustotal.com/api/v3"
RATE_LIMIT_DELAY = 30  # Respeita limite gratuito (4 req/min)


def validate_env() -> str:
    """Valida e retorna a chave API do VirusTotal"""
    api_key = os.getenv('VT_API_KEY', '').strip()
    if not api_key:
        raise ValueError("VT_API_KEY não configurada. Defina no arquivo .env")
    return api_key


def is_supported_file(file_path: Path) -> tuple[bool, str]:
    """Verificação robusta de tipos suportados com tratamento de erros"""
    ext = file_path.suffix.lower()

    if ext not in SUPPORTED_EXTENSIONS:
        return False, f"Extensão não suportada: {ext}"

    try:
        # Validação de tamanho
        file_size = file_path.stat().st_size
        if file_size < MIN_FILE_SIZE:
            return False, f"Tamanho inválido ({file_size} bytes < {MIN_FILE_SIZE} bytes)"
        if file_size > MAX_FILE_SIZE:
            return False, f"Excede limite de 32MB ({file_size} bytes)"

        # Validação MIME precisa
        mime = magic.Magic(mime=True)
        detected_mime = mime.from_file(str(file_path))

        if detected_mime != SUPPORTED_MIME[ext]:
            return False, (
                f"MIME incorreto para {ext}: esperado '{SUPPORTED_MIME[ext]}', "
                f"encontrado '{detected_mime}'"
            )

        return True, SUPPORTED_EXTENSIONS[ext]

    except Exception as e:
        return False, f"Erro na verificação: {str(e).split(':')[0]}"


def analyze_file(api_key: str, filepath: Path, relative_path: Path, doc_type: str) -> dict:
    """Processa um único arquivo com tratamento completo de erros"""
    result = {
        'filename': filepath.name,
        'relative_path': str(relative_path),
        'size': filepath.stat().st_size,
        'doc_type': doc_type,
        'status': 'pending',
        'malicious': 0,
        'suspicious': 0,
        'total_engines': 0,
        'action': 'Ignorado',
        'error': ''
    }

    try:
        # Upload do arquivo
        with open(filepath, 'rb') as f:
            response = requests.post(
                f"{API_URL}/files",
                headers={'x-apikey': api_key},
                files={'file': (filepath.name, f)},
                timeout=30
            )
            response.raise_for_status()
            analysis_id = response.json()['data']['id']

        # Polling com tratamento de limites
        for _ in range(5):
            time.sleep(15)
            response = requests.get(
                f"{API_URL}/analyses/{analysis_id}",
                headers={'x-apikey': api_key},
                timeout=10
            )
            response.raise_for_status()

            report = response.json()['data']
            if report['attributes']['status'] == 'completed':
                stats = report['attributes']['stats']
                result.update({
                    'status': 'completed',
                    'malicious': stats['malicious'],
                    'suspicious': stats['suspicious'],
                    'total_engines': sum(stats.values())
                })
                break

        # Decisão de ação com tratamento de greyware
        if result['status'] == 'completed':
            MIN_POSITIVES = int(os.getenv("VT_MIN_POSITIVES", "1"))
            IGNORE_SUSPICIOUS = os.getenv("VT_IGNORE_SUSPICIOUS", "false").lower() == "true"

            positives = result['malicious'] + (0 if IGNORE_SUSPICIOUS else result['suspicious'])

            if positives >= MIN_POSITIVES:
                try:
                    filepath.unlink(missing_ok=True)
                    result['action'] = (
                        f"DELETADO ({result['malicious']} maliciosos, "
                        f"{result['suspicious']} suspeitos)"
                    )
                except Exception as e:
                    result['error'] = f"Erro ao excluir: {str(e)[:50]}"
                    result['action'] = "Falha na exclusão"
            else:
                result['action'] = "Mantido"
        else:
            result['error'] = "Análise não concluída"

    except RequestException as e:
        status_code = e.response.status_code if e.response else 'N/A'
        result['error'] = f"API Error {status_code}"
    except Exception as e:
        result['error'] = f"Erro crítico: {str(e)[:50]}"

    return result


def generate_report(directory: Path, results: list, invalid_files: list, quarantine_dir: Path = None):
    """Gera relatório CSV com formatação consistente e histórico de ações"""
    report_path = directory / 'relatorio_virustotal.csv'

    with open(report_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Caminho Relativo', 'Arquivo', 'Tamanho (KB)', 'Maliciosos', 'Suspeitos',
            'Ação', 'Tipo de documento', 'Status', 'Erro', 'Local Final'
        ])

        # Adiciona informações de quarentena aos resultados
        for r in results:
            final_location = r['relative_path']
            if "DELETADO" in r['action'] and quarantine_dir:
                final_location = f"QUARENTENA: {quarantine_dir.name}/{r['relative_path']}"
            writer.writerow([
                r['relative_path'],
                r['filename'],
                f"{r['size'] / 1024:.1f}",
                r['malicious'],
                r['suspicious'],
                r['action'],
                r['doc_type'],
                r['status'],
                r['error'],
                final_location
            ])

        # Processa arquivos ignorados
        for rel_path, name, reason in invalid_files:
            final_location = rel_path
            if quarantine_dir:
                final_location = f"QUARENTENA: {quarantine_dir.name}/{rel_path}"
            writer.writerow([
                rel_path, name, 'N/A', 'N/A', 'N/A',
                'Ignorado', 'N/A', 'Invalido', reason, final_location
            ])


def handle_quarantine(base_dir: Path, invalid_files: list) -> Path:
    """Move arquivos ignorados para quarentena com estrutura preservada"""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    quarantine_dir = base_dir / f"quarantine_{timestamp}"

    try:
        quarantine_dir.mkdir(exist_ok=True, parents=True)
        print(f"\n  🧪 Criando pasta de quarentena: {quarantine_dir}")

        moved_count = 0
        failed = []

        for rel_path, name, _ in invalid_files:
            source = base_dir / rel_path
            dest = quarantine_dir / rel_path

            # Garante que diretórios de destino existam
            dest.parent.mkdir(exist_ok=True, parents=True)

            try:
                move(source, dest)
                moved_count += 1
            except Exception as e:
                failed.append((source, str(e)))

        print(f"  ✅ {moved_count} arquivos movidos para quarentena")
        if failed:
            print(f"  ⚠️  {len(failed)} arquivos não puderam ser movidos:")
            for i, (src, err) in enumerate(failed[:3], 1):
                print(f"     [{i}] {src}: {err}")
            if len(failed) > 3:
                print(f"     ... e mais {len(failed) - 3}")

        return quarantine_dir

    except Exception as e:
        print(f"  ❌ Falha ao criar quarentena: {str(e)}")
        return None


def collect_files(base_dir: Path, include_subfolders: bool) -> tuple[list, list]:
    """
    Coleta arquivos válidos e inválidos com suporte a subpastas

    Args:
        base_dir: Diretório raiz para análise
        include_subfolders: Se deve incluir subpastas

    Returns:
        (valid_files, invalid_files) onde:
        - valid_files: [(file_path, relative_path, doc_type), ...]
        - invalid_files: [(relative_path, filename, reason), ...]
    """
    valid_files = []
    invalid_files = []

    # Define o padrão de busca
    search_pattern = "**/*" if include_subfolders else "*"

    # Coleta todos os arquivos (respeitando permissões)
    try:
        for file_path in base_dir.glob(search_pattern):
            if not file_path.is_file():
                continue

            # Calcula caminho relativo para rastreabilidade
            try:
                relative_path = file_path.relative_to(base_dir)
            except ValueError:
                # Para casos onde symlink aponta para fora do diretório base
                relative_path = Path("...") / file_path.name

            is_valid, reason = is_supported_file(file_path)
            if is_valid:
                valid_files.append((file_path, relative_path, reason))
            else:
                invalid_files.append((str(relative_path), file_path.name, reason))
    except PermissionError:
        print(f" ⚠️  Permissão negada para acessar {base_dir} - pulando este diretório")

    return valid_files, invalid_files


def main():
    print("🔍 Verificador de Documentos com VirusTotal API (v3.3)")
    print("============================================\n")

    # Validação de ambiente
    try:
        api_key = validate_env()
    except ValueError as e:
        print(f"🔑 ERRO: {str(e)}")
        print("  Crie um arquivo .env com: VT_API_KEY=sua_chave_aqui")
        return

    # Entrada de diretório
    directory = Path(input("📁 Insira o caminho completo do diretório: ").strip())
    if not directory.is_dir():
        print(f"  ❌ ERRO: '{directory}' não é um diretório válido")
        return

    # Pergunta sobre subpastas
    while True:
        include_subfolders = input(
            "🔍 Incluir subpastas na análise? (s/n) [n]: "
        ).strip().lower() or 'n'

        if include_subfolders in ['s', 'n']:
            include_subfolders = (include_subfolders == 's')
            break
        print("  ⚠️ Resposta inválida. Use 's' para sim ou 'n' para não.")

    # Coleta e validação de arquivos
    print(f"\n  🔍 {'Varrendo diretório e subpastas...' if include_subfolders else 'Varrendo diretório...'}")
    valid_files, invalid_files = collect_files(directory, include_subfolders)

    # Resumo inicial
    print(f"\n  ✅ {len(valid_files)} arquivos válidos identificados")
    print(f"  ⚠️  {len(invalid_files)} arquivos ignorados")

    if not valid_files:
        print(f"  ❌ Nenhum arquivo suportado encontrado em: {directory}")
        return

    # Resumo hierárquico (mostra distribuição por diretório)
    if include_subfolders and valid_files:
        dir_counter = {}
        for _, rel_path, _ in valid_files:
            parent_dir = str(rel_path.parent)
            dir_counter[parent_dir] = dir_counter.get(parent_dir, 0) + 1

        print("\n  Distribuição por diretório:")
        for path, count in sorted(dir_counter.items(), key=lambda x: x[1], reverse=True)[:3]:
            display_path = path if len(path) < 50 else f"...{path[-47:]}"
            print(f"   • {display_path}: {count} arquivos")
        if len(dir_counter) > 3:
            print(f"   ... e mais {len(dir_counter) - 3} diretórios")

    print("\n  Iniciando análise (isso pode levar tempo)...")

    # Processamento paralelo controlado
    results = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            executor.submit(
                analyze_file,
                api_key,
                file_path,
                relative_path,
                doc_type
            ): (file_path, relative_path)
            for file_path, relative_path, doc_type in valid_files
        }

        for i, future in enumerate(as_completed(futures), 1):
            file_path, relative_path = futures[future]
            try:
                result = future.result()
                status_emoji = "❌" if "DELETADO" in result['action'] else "✅"
                # Mostra caminho relativo truncado para não poluir a saída
                rel_path_display = str(relative_path)
                if len(rel_path_display) > 40:
                    rel_path_display = f"...{rel_path_display[-37:]}"

                print(
                    f"  [{i}/{len(valid_files)}] {status_emoji} {rel_path_display} "
                    f"({result['malicious']}/{result['suspicious']}) - {result['action']}"
                )
                results.append(result)
            except Exception as e:
                print(f"  [{i}/{len(valid_files)}] ⚠️  Erro processando {file_path.name}: {str(e)[:50]}")

            # Respeita limite de taxa entre requisições
            if i < len(valid_files):
                time.sleep(RATE_LIMIT_DELAY)

    # Geração de relatório
    quarantine_dir = None
    generate_report(directory, results, invalid_files, quarantine_dir)

    # Estatísticas finais
    deleted = sum(1 for r in results if "DELETADO" in r['action'])
    errors = sum(1 for r in results if r['error'])
    suspicious_files = sum(1 for r in results if r['suspicious'] > 0 and r['malicious'] == 0)

    print(f"\n{'─' * 50}")
    print(f"✅ Relatório salvo em: {directory / 'relatorio_virustotal.csv'}")
    print(f"\n📊 Resultados:")
    print(f" • {len(valid_files)} documentos analisados")
    print(f" • {deleted} arquivos deletados")
    print(f" • {suspicious_files} arquivos com greyware detectado")
    print(f" • {errors} erros de processamento")
    print(f" • {len(invalid_files)} arquivos não suportados")

    # GESTÃO DE ARQUIVOS IGNORADOS
    if invalid_files:
        print("\n⚠️  Arquivos ignorados (não suportados):")
        for i, (rel_path, name, reason) in enumerate(invalid_files[:5], 1):
            print(f"  [{i}] {rel_path}/{name} - {reason}")
        if len(invalid_files) > 5:
            print(f"  ... e mais {len(invalid_files) - 5} arquivos")

        # Pergunta sobre ação para arquivos ignorados
        while True:
            action = input(
                "\nDeseja mover os arquivos ignorados para uma pasta de quarentena? (s/n) [n]: "
            ).strip().lower() or 'n'

            if action in ['s', 'n']:
                if action == 's':
                    quarantine_dir = handle_quarantine(directory, invalid_files)
                    # Atualiza relatório com informações de quarentena
                    generate_report(directory, results, invalid_files, quarantine_dir)
                break
            print("  ⚠️ Resposta inválida. Use 's' para sim ou 'n' para não.")

    print(f"\n{'─' * 50}")
    print("✅ Processo concluído com sucesso!")
    print(f"  • Relatório: {directory / 'relatorio_virustotal.csv'}")
    if quarantine_dir:
        print(f"  • Quarentena: {quarantine_dir}")


if __name__ == "__main__":
    try:
        start_time = time.time()
        main()
        print(f"\n⏱️ Tempo total: {time.time() - start_time:.1f} segundos")
    except KeyboardInterrupt:
        print("\n\n❌ Execução interrompida pelo usuário")
        exit(1)
    except Exception as e:
        print(f"\n💥 Erro crítico: {str(e)}")
        exit(1)
